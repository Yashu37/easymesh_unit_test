/*
 * TEST RUNNER: cac_print_test
 *
 * Poisoned around the call:
 *   - the caller's format buffer past its NUL;
 *   - the caller's %s argument buffer past its NUL.
 * buff[256] is internal (auto-guarded by ASan stack redzones); the unbounded
 * vsprintf overflow of buff is what we are probing.
 *
 * The "long_s" case is expected to overflow buff[256] (reproducer); the
 * shorter cases fit and return cleanly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void cac_print(char *format, ...);

int test_cac_print(const cac_print_test_case_t *tc)
{
    size_t flen = strlen(cac_fmt_buf) + 1;
    size_t alen = strlen(cac_arg_buf) + 1;

    /* POISON */
    __asan_poison_memory_region(&cac_fmt_buf[flen], CAC_FMT_MAX + CAC_PAD - flen);
    if (tc->arg_len > 0) __asan_poison_memory_region(&cac_arg_buf[alen], CAC_ARG_MAX + CAC_PAD - alen);
    printf("    (calling fmt=\"%.10s\" arg_len=%d)\n", tc->fmt, tc->arg_len);
    fflush(stdout);

    if (tc->arg_len > 0) cac_print(cac_fmt_buf, cac_arg_buf);
    else                 cac_print(cac_fmt_buf);

    /* UNPOISON */
    if (tc->arg_len > 0) __asan_unpoison_memory_region(&cac_arg_buf[alen], CAC_ARG_MAX + CAC_PAD - alen);
    __asan_unpoison_memory_region(&cac_fmt_buf[flen], CAC_FMT_MAX + CAC_PAD - flen);

    printf("    returned (no overflow detected)\n");
    return 1;
}

void run_all_tests_cac_print(void)
{
    for (int i = 0; cac_print_suite[i].test_name != NULL; i++) {
        cac_print_test_case_t *test = &cac_print_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_cac_print_input(test);
        int pass = test_cac_print(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    remove(cac_log_path);
}
