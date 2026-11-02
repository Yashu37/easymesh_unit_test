/*
 * TEST RUNNER: pipe_read_oper_thread_func_test
 * Poison: fifo_path slot past 64; p_app past its size. fifo_path[64] and the
 * VLA buffer[buffer_len] are ASan-stack guarded (read/memset intercepted).
 * PASS = returns NULL; the one-read case decodes/processes once.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void *pipe_read_oper_thread_func(void *arg);

int test_pipe_read_oper_thread_func(const pipe_read_oper_thread_func_test_case_t *tc)
{
    __asan_poison_memory_region(&prt_slot[PRT_PATH_SZ], PRT_PAD);
    __asan_poison_memory_region(&prt_app_buf[sizeof(wifi_app_t)], PRT_PAD);

    void *ret = pipe_read_oper_thread_func(prt_app_buf);

    __asan_unpoison_memory_region(&prt_app_buf[sizeof(wifi_app_t)], PRT_PAD);
    __asan_unpoison_memory_region(&prt_slot[PRT_PATH_SZ], PRT_PAD);

    char path[64]; snprintf(path, sizeof(path), "/tmp/csi_motion_pipe%d", tc->session); remove(path);
    printf("    ret=%p decode=%d process=%d clean=%d\n", ret, prt_decode_calls, prt_process_calls, prt_clean_calls);
    return ret == NULL && prt_decode_calls == tc->expect_decode;
}

void run_all_tests_pipe_read_oper_thread_func(void)
{
    for (int i = 0; pipe_read_oper_thread_func_suite[i].test_name != NULL; i++) {
        pipe_read_oper_thread_func_test_case_t *test = &pipe_read_oper_thread_func_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_pipe_read_oper_thread_func_input(test);
        int pass = test_pipe_read_oper_thread_func(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
