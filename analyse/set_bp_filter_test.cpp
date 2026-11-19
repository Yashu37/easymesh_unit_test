/*
 * TEST RUNNER: set_bp_filter_test
 *
 * Poisoned around the call: SBF_GUARD bytes before and after em_t::m_ruid (the members around the interface name / mac
 * / media) - a %s read of the 32-byte name that has no NUL walks out of m_ruid into the guard and is reported. The handler's
 * locals (mreq, the static bpfcode[]) are covered by ASan redzones. PASS = return value, number of setsockopt() / close()
 * calls, the membership ifindex, the attached BPF program and m_fd afterwards match. Cases named crash_* ABORT on the original
 * handler: they run last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "set_bp_filter.h"

namespace sbf {
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }
static void poison(bool on)
{
    poison_region(g_em->before_ruid, sizeof(g_em->before_ruid), on);     /* members before m_ruid */
    poison_region(g_em->after_ruid, sizeof(g_em->after_ruid), on);       /* members after m_ruid */
}
static void call_once(void) { poison(true); invoke(); poison(false); }

static int filter_ok(void)
{
    const sso_rec_t *r = &g_rec[0];
    if (r->level != SOL_SOCKET || r->optname != SO_ATTACH_FILTER || r->len != 4) return 0;
    const struct sock_filter e[4] = { { BPF_LD | BPF_H | BPF_ABS, 0, 0, 12 }, { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, ETH_P_1905 },
                                      { BPF_RET | BPF_K, 0, 0, 0xffffffff }, { BPF_RET | BPF_K, 0, 0, 0 } };
    if (memcmp(r->insn, e, sizeof(e)) != 0) return 0;
    if (g_ncalls >= 2) { const sso_rec_t *m = &g_rec[1]; if (m->level != SOL_PACKET || m->optname != PACKET_ADD_MEMBERSHIP || m->mr_type != PACKET_MR_PROMISC) return 0; }
    return 1;
}
static int test_one(const test_case_t *tc)
{
    call_once();
    int ok = g_ret == tc->expect_ret && g_ncalls == tc->expect_calls && g_nclose == tc->expect_close;
    if (tc->expect_ifindex >= 0 && g_ncalls >= 2) ok = ok && g_rec[1].ifindex == tc->expect_ifindex;
    if (g_ncalls >= 1) ok = ok && g_rec[0].fd == tc->fd && (g_ncalls < 2 || g_rec[1].fd == tc->fd);
    if (g_nclose) ok = ok && g_close_fd == tc->fd;
    if (tc->check_filter) ok = ok && filter_ok();
    if (tc->expect_fd_after != -2) ok = ok && g_em->m_fd == tc->expect_fd_after;
    printf("    ret=%d (expect %d) setsockopt=%d (expect %d) close=%d (expect %d) m_fd=%d\n", g_ret, tc->expect_ret, g_ncalls, tc->expect_calls, g_nclose, tc->expect_close, g_em->m_fd);
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
} /* namespace sbf */

void run_all_tests_set_bp_filter(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; sbf::suite[i].test_name != NULL; i++) {
        sbf::test_case_t *test = &sbf::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        sbf::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = sbf::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = sbf::test_one(test);
        sbf::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("set_bp_filter: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
