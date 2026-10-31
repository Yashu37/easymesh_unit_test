/*
 * TEST RUNNER: parse_uri_test
 *
 * parse_uri has three caller-owned buffers, all poisoned here:
 *   - input  uri  : poison the tail past its terminator (over-read guard)
 *   - output proto: backed by 128 bytes, only proto_size handed in, tail
 *                   past proto_size poisoned (over-write guard)
 *   - output host : backed by 512 bytes, only host_size handed in, tail
 *                   past host_size poisoned (over-write guard)
 * The internal tmp[512] is auto-guarded by ASan.
 *
 * expect_ret == -1 marks a case we SUSPECT crashes (strtok_r returns NULL
 * for tproto -> strcmp(NULL,...)); such a case aborts the run if the bug
 * is present, so these are ordered last.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool parse_uri(char *uri, char *proto, size_t proto_size,
               char *host, size_t host_size, int *port);

#define PROTO_SIZE 16
#define HOST_SIZE  64

static char protobuf[128];
static char hostbuf[512];

int test_parse_uri(const parse_uri_test_case_t *tc)
{
    int port = 0;

    /* poison input tail (over-read guard) */
    __asan_poison_memory_region(&puri_in[puri_in_len + 1],
                                sizeof(puri_in) - (puri_in_len + 1));
    /* poison output tails beyond the sizes we hand in (over-write guard) */
    memset(protobuf, 0, sizeof(protobuf));
    memset(hostbuf, 0, sizeof(hostbuf));
    __asan_poison_memory_region(&protobuf[PROTO_SIZE], sizeof(protobuf) - PROTO_SIZE);
    __asan_poison_memory_region(&hostbuf[HOST_SIZE],   sizeof(hostbuf)  - HOST_SIZE);

    if (tc->expect_ret == -1)
        printf("    (this case is suspected to crash via strcmp(NULL,...))\n");

    bool ret = parse_uri(puri_in, protobuf, PROTO_SIZE, hostbuf, HOST_SIZE, &port);

    __asan_unpoison_memory_region(&protobuf[PROTO_SIZE], sizeof(protobuf) - PROTO_SIZE);
    __asan_unpoison_memory_region(&hostbuf[HOST_SIZE],   sizeof(hostbuf)  - HOST_SIZE);
    __asan_unpoison_memory_region(&puri_in[puri_in_len + 1],
                                  sizeof(puri_in) - (puri_in_len + 1));

    printf("    ret=%d proto=\"%s\" host=\"%s\" port=%d\n",
           ret, ret ? protobuf : "", ret ? hostbuf : "", port);
    return ret ? 1 : 0;
}

void run_all_tests_parse_uri(void)
{
    for (int i = 0; parse_uri_suite[i].test_name != NULL; i++) {
        parse_uri_test_case_t *test = &parse_uri_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_parse_uri_input(test);

        int got = test_parse_uri(test);

        if (test->expect_ret == -1) {
            /* reached here => no crash on a case we thought might crash */
            printf("===== %s: \033[33mNO CRASH\033[0m (returned %d) =====\n", test->test_name, got);
        } else if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
