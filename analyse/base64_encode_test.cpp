/*
 * TEST RUNNER: base64_encode_test
 *
 * Same shape as the other *_test.cpp runners: poison the unused tail of
 * both the input and output buffers, call the handler, unpoison, then
 * compare against the expected return value. The function is NOT modified
 * -- if it reads/writes out of bounds the run aborts here.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

ssize_t base64_encode(char *out, ssize_t out_sz, void *input, ssize_t input_sz);

int test_base64_encode(void)
{
    /* Poison input bytes at/above input_sz  -> any over-read is flagged.
     * Poison output bytes at/above out_sz    -> any over-write is flagged.
     * The global red-zones around the arrays catch an access below index 0. */
    __asan_poison_memory_region(&b64e_in[b64e_in_sz],   sizeof(b64e_in)  - b64e_in_sz);
    __asan_poison_memory_region(&b64e_out[b64e_out_sz], sizeof(b64e_out) - b64e_out_sz);

    ssize_t ret = base64_encode(b64e_out, b64e_out_sz, b64e_in, b64e_in_sz);

    __asan_unpoison_memory_region(&b64e_in[b64e_in_sz],   sizeof(b64e_in)  - b64e_in_sz);
    __asan_unpoison_memory_region(&b64e_out[b64e_out_sz], sizeof(b64e_out) - b64e_out_sz);

    printf("ret=%zd\n", ret);
    return (int)ret;
}

void run_all_tests_base64_encode(void)
{
    for (int i = 0; base64_encode_suite[i].test_name != NULL; i++) {
        base64_enc_test_case_t *test = &base64_encode_suite[i];

        printf("--- Running Test: %s  in_sz=%zd out_sz=%zd ---\n",
               test->test_name, (ssize_t)test->in_sz, (ssize_t)test->out_sz);

        construct_base64_encode_input(test);

        int ret = test_base64_encode();

        if (ret == test->expected_result) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expected_result, ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
