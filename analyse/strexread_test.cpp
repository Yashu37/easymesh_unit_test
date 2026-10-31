/*
 * TEST RUNNER: strexread_test
 *
 * fd[2] is internal (pipe, indexed [0]/[1]); the caller-owned inputs are
 * prog and the argv array, so those are poisoned:
 *   - prog: poison the tail past its terminator (over-read guard)
 *   - argv: poison the slots past the NULL terminator (over-read guard)
 * The returned output buffer is heap-allocated inside strexread and
 * auto-guarded by ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char *strexread(const char *prog, const char *const*argv);

int test_strexread(const strexread_test_case_t *tc)
{
    const char *prog = sxr_prog_null ? NULL : sxr_prog;
    const char *const *argv = sxr_argv_null ? NULL : sxr_argv;

    /* poison prog's tail past the terminator */
    if (!sxr_prog_null)
        __asan_poison_memory_region(&sxr_prog[sxr_prog_len + 1],
                                    sizeof(sxr_prog) - (sxr_prog_len + 1));
    /* poison argv slots past the NULL terminator (argv[sxr_argc] is NULL) */
    if (!sxr_argv_null) {
        size_t used = (size_t)(sxr_argc + 1);   /* entries incl. the NULL */
        if (used < 8)
            __asan_poison_memory_region(&sxr_argv[used],
                                        (8 - used) * sizeof(sxr_argv[0]));
    }

    char *out = strexread(prog, argv);

    if (!sxr_prog_null)
        __asan_unpoison_memory_region(&sxr_prog[sxr_prog_len + 1],
                                      sizeof(sxr_prog) - (sxr_prog_len + 1));
    if (!sxr_argv_null) {
        size_t used = (size_t)(sxr_argc + 1);
        if (used < 8)
            __asan_unpoison_memory_region(&sxr_argv[used],
                                          (8 - used) * sizeof(sxr_argv[0]));
    }

    int nonnull = (out != NULL) ? 1 : 0;
    printf("    out=%s%s\n", nonnull ? "non-NULL len=" : "(null)",
           nonnull ? "" : "");
    if (out) { printf("      bytes=%zu\n", strlen(out)); free(out); }
    return nonnull;
}

void run_all_tests_strexread(void)
{
    for (int i = 0; strexread_suite[i].test_name != NULL; i++) {
        strexread_test_case_t *test = &strexread_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_strexread_input(test);

        int got = test_strexread(test);

        if (got == test->expect_nonnull) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected nonnull=%d, got=%d) =====\n",
                   test->test_name, test->expect_nonnull, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
