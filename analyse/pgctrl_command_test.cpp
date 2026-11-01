/*
 * TEST RUNNER: pgctrl_command_test
 *
 * Poisoned around the call (caller-owned inputs): file, format and the %s
 * argument past their NUL, and the cmd vsnprintf slot pgc_slot and the
 * write() capture buffer pgc_out past 512.
 * cmd[512] is internal (auto-guarded by ASan).
 * PASS = return matches and the bytes written match (<= 511).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int pgctrl_command(char *file, char *format, ...);

static void psn(char *b, size_t sz, int on)
{
    size_t l = strlen(b);
    if (on) __asan_poison_memory_region(b + l + 1, sz - (l + 1));
    else    __asan_unpoison_memory_region(b + l + 1, sz - (l + 1));
}

int test_pgctrl_command(const pgctrl_command_test_case_t *tc)
{
    psn(pgc_file, sizeof(pgc_file), 1);
    psn(pgc_fmt, sizeof(pgc_fmt), 1);
    psn(pgc_arg, sizeof(pgc_arg), 1);
    __asan_poison_memory_region(&pgc_slot[PGC_SLOT_SZ], PGC_SLOT_PAD);   /* cmd vsnprintf slot */
    __asan_poison_memory_region(&pgc_out[PGC_SLOT_SZ], PGC_SLOT_PAD);    /* write() capture */

    int ret = pgctrl_command(pgc_file, pgc_fmt, pgc_arg, 7);

    __asan_unpoison_memory_region(&pgc_out[PGC_SLOT_SZ], PGC_SLOT_PAD);
    __asan_unpoison_memory_region(&pgc_slot[PGC_SLOT_SZ], PGC_SLOT_PAD);
    psn(pgc_arg, sizeof(pgc_arg), 0);
    psn(pgc_fmt, sizeof(pgc_fmt), 0);
    psn(pgc_file, sizeof(pgc_file), 0);

    printf("    ret=%d vsnprintf_ret=%d written=%zu path_len=%zu\n", ret, pgc_vs_ret, pgc_out_len, pgc_open_path_len);
    return ret == tc->expect_ret && pgc_out_len == (size_t)tc->expect_out && pgc_out_len <= 511;
}

void run_all_tests_pgctrl_command(void)
{
    for (int i = 0; pgctrl_command_suite[i].test_name != NULL; i++) {
        pgctrl_command_test_case_t *test = &pgctrl_command_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_pgctrl_command_input(test);

        int pass = test_pgctrl_command(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d written=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_out);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
