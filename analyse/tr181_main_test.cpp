/*
 * TEST RUNNER: tr181_main_test
 *
 * Poisoned around the call: TMO_GUARD bytes in front of and behind the scripted stdin values, and in front of and behind every heap object
 * main allocates (main's calloc / strdup are the tracked ones from tr181_main.cpp, whose guards are poisoned while the object is alive),
 * so a scanf beyond the script or a write past one of main's SetSSID objects is reported; main's service_name[] local is covered by an
 * ASan redzone. PASS = the recorded bus calls, the SetSSID object contents, the number of heap objects main still owns when the run
 * ends and how main returned. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops with
 * the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "tr181_main.h"

namespace tmo {
static void poison(bool on)
{
    void *r[2] = { (char *)g_script - TMO_GUARD, (char *)g_script + 8 * sizeof(int) };
    for (int i = 0; i < 2; i++) { if (on) __asan_poison_memory_region(r[i], TMO_GUARD); else __asan_unpoison_memory_region(r[i], TMO_GUARD); }
}
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    int ok = g_seq == tc->expect_seq;
    if (tc->expect_returned == -1) ok = ok && !g_returned;
    else if (tc->expect_returned == 0) ok = ok && g_returned && g_ret == 0;
    else ok = ok && g_returned && g_ret != 0;
    if (tc->expect_seq && strchr(tc->expect_seq, 'I') && !tc->invoke_rc) ok = ok && g_inv_ok;
    if (tc->expect_seq && strchr(tc->expect_seq, 'S') && !tc->subs_rc) ok = ok && g_subs_ok;
    if (tc->expect_live >= 0) ok = ok && (int)g_live.size() == tc->expect_live;
    if (tc->expect_no_hang) ok = ok && !g_hung;
    printf("    calls=\"%s\" (expect \"%s\") returned=%d ret=%d live_heap_objects=%zu hung=%d eof_reads=%d\n", g_seq.c_str(), tc->expect_seq, g_returned, g_ret, g_live.size(), g_hung, g_eof_calls);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { poison(true); invoke(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan above)" : "survived", st);
    return aborted;
}
} /* namespace tmo */

void run_all_tests_tr181_main(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; tmo::suite[i].test_name != NULL; i++) {
        tmo::test_case_t *test = &tmo::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        tmo::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = tmo::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = tmo::test_one(test);
        tmo::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("tr181_main: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
