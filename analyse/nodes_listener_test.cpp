/*
 * TEST RUNNER: nodes_listener_test
 *
 * Poisoned around the call:
 *   - NLS_GUARD bytes before and after em_mgr_t::m_rset (the members next to the fd_set) - FD_SET / FD_ISSET of an fd
 *     >= FD_SETSIZE (1024) writes / reads beyond the 128-byte fd_set and is reported;
 *   - the handler's local buff[3072] is covered by an ASan redzone: the proto_process stub walks `len` bytes of it, so a
 *     length of 0xFFFFFFFF (read() returned -1) is reported.
 * PASS = number of proto_process() calls, length of the first call and nfds of the first select() match. Cases named crash_*
 * ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "nodes_listener.h"

namespace nls {
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }
static void poison(bool on)
{
    poison_region(g_mgr->before_rset, sizeof(g_mgr->before_rset), on);     /* members before m_rset */
    poison_region(g_mgr->after_rset, sizeof(g_mgr->after_rset), on);       /* members after m_rset */
}
static void call_once(void) { poison(true); invoke(); poison(false); }

static int test_one(const test_case_t *tc)
{
    call_once();
    int ok = g_calls == tc->expect_calls;
    if (tc->expect_len0 >= 0) ok = ok && g_len0 == tc->expect_len0;
    if (tc->expect_nfds >= 0) ok = ok && g_nfds0 == tc->expect_nfds;
    printf("    calls=%d (expect %d) len0=%ld (expect %ld) nfds=%d (expect %d)\n", g_calls, tc->expect_calls, g_len0, tc->expect_len0, g_nfds0, tc->expect_nfds);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    (void)tc; fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}
} /* namespace nls */

void run_all_tests_nodes_listener(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; nls::suite[i].test_name != NULL; i++) {
        nls::test_case_t *test = &nls::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        nls::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = nls::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = nls::test_one(test);
        nls::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("nodes_listener: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
