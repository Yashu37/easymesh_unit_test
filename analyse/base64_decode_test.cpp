/*
 * TEST RUNNER: base64_decode_test
 *
 * Same shape as get_first_tlv_test.cpp: a test_* function that poisons the
 * unused buffer tail with ASan, calls the handler, unpoisons; plus a
 * run_all_tests_* driver that walks the suite and prints PASS/FAIL.
 *
 * Here the poisoned region is b64_out[b64_out_sz .. 4096], so any write at
 * or beyond the output-array size is an ASan error. The function is NOT
 * modified -- if it reads/writes out of bounds the run aborts here.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

ssize_t base64_decode(void *out, ssize_t out_sz, char *input);

int test_base64_decode(void)
{
    /* Poison every output byte at/above the declared size: a write to
     * b64_out[b64_out_sz] or beyond (index >= array size) is flagged.
     * The global red-zone around b64_out catches a write below index 0. */
    __asan_poison_memory_region(&b64_out[b64_out_sz], sizeof(b64_out) - b64_out_sz);

    ssize_t ret = base64_decode(b64_out, b64_out_sz, b64_input);

    __asan_unpoison_memory_region(&b64_out[b64_out_sz], sizeof(b64_out) - b64_out_sz);

    printf("ret=%zd\n", ret);
    return (int)ret;
}

void run_all_tests_base64_decode(void)
{
    for (int i = 0; base64_decode_suite[i].test_name != NULL; i++) {
        base64_test_case_t *test = &base64_decode_suite[i];

        printf("--- Running Test: %s  input=\"%s\" out_sz=%zd ---\n",
               test->test_name, test->input, (ssize_t)test->out_sz);

        /* 1. Load this case's input + output size */
        construct_base64_input(test);

        /* 2. Run the handler under ASan (may abort here on OOB) */
        int ret = test_base64_decode();

        /* 3. Compare against expected (only reached if no crash) */
        if (ret == test->expected_result) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expected_result, ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
