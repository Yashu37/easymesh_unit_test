/*
 * TEST RUNNER: sta_compare_db_test
 *
 * Poisoned around the call: for every scripted cell the SCD_GUARD bytes before and after its string buffer and the buffer tail past
 * the string's NUL, so get_string()/strlen()/unhex() reading outside the cell is reported. The handler's mac[18] local is covered by
 * ASan redzones: a MAC column longer than the buffer is reported. PASS = compare_db returns the expected bool. clamp_* cases ABORTED on the original code: they run last and
 * UNFORKED so a plain `make` stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "sta_compare_db.h"

namespace scd {
static void poison(bool on)
{
    for (int r = 0; r < SCD_ROWS; r++) for (int c = 0; c < SCD_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) { __asan_poison_memory_region(x->before, SCD_GUARD); __asan_poison_memory_region(x->after, SCD_GUARD); __asan_poison_memory_region(x->s + used, SCD_CELL_SZ - used); }
        else    { __asan_unpoison_memory_region(x->before, SCD_GUARD); __asan_unpoison_memory_region(x->after, SCD_GUARD); __asan_unpoison_memory_region(x->s + used, SCD_CELL_SZ - used); }
    }
}
static int test_one(const test_case_t *tc)
{
    poison(true); bool r = invoke(tc); poison(false);
    printf("    returned %d (expect %d), get_string calls %d\n", (int)r, (int)tc->expect_ret, g_gs_calls); fflush(stdout);
    if (tc->skip_row && g_gs_calls != 0) { printf("    the row was not skipped (get_string was called)\n"); return 0; }
    return r == tc->expect_ret;
}
static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { poison(true); invoke(tc); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan above)" : "survived", st);
    return aborted;
}
} /* namespace scd */

void run_all_tests_sta_compare_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; scd::suite[i].test_name != NULL; i++) {
        scd::test_case_t *test = &scd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        scd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = scd::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = scd::test_one(test);
        scd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("sta_compare_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
