/*
 * TEST RUNNER: policy_sync_db_test
 *
 * Poisoned around the call: for every scripted cell, the SPL_GUARD bytes before and after its string buffer and the buffer tail
 * past the string's NUL - get_string()/snprintf/strlen reading outside the cell is reported. The handler's locals (str[128],
 * sta_mac_list_str[1024], token_parts[16], sta_mac_str[16][64], policy) are covered by ASan redzones, so a DB string longer than
 * the caller's buffer or a token count above 16 is reported. PASS = number of recorded policies, num_sta, first STA MAC, interval
 * and second-row num_sta match. Cases named crash_* ABORT on the original code: they run last and UNFORKED so a plain `make`
 * stops with the ASan report / assertion; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "policy_sync_db.h"

namespace spl {
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }
static void poison(bool on)
{
    for (int r = 0; r < SPL_ROWS; r++) for (int c = 0; c < SPL_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        poison_region(x->before, SPL_GUARD, on);                                   /* before the cell */
        poison_region(x->after, SPL_GUARD, on);                                    /* after the cell */
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) __asan_poison_memory_region(x->s + used, SPL_CELL_SZ - used);      /* tail past the NUL */
        else    __asan_unpoison_memory_region(x->s + used, SPL_CELL_SZ - used);
    }
}
static void call_once(void) { poison(true); invoke(); poison(false); }

static int test_one(const test_case_t *tc)
{
    call_once();
    auto &u = dm_policy_list_t::g_updates;
    int ok = (int)u.size() == tc->expect_updates;
    if (tc->expect_num_sta >= 0 && !u.empty()) ok = ok && (int)u[0].num_sta == tc->expect_num_sta;
    if (tc->expect_mac0 && !u.empty()) { char m[24]; unsigned char *b = u[0].sta_mac[0]; snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]); ok = ok && !strcmp(m, tc->expect_mac0); }
    if (tc->expect_interval >= 0 && !u.empty()) ok = ok && (int)u[0].interval == tc->expect_interval;
    if (tc->expect_num_sta2 >= 0 && u.size() >= 2) ok = ok && (int)u[1].num_sta == tc->expect_num_sta2;
    printf("    updates=%zu (expect %d) num_sta=%d (expect %d) interval=%d num_sta2=%d\n", u.size(), tc->expect_updates, u.empty() ? -1 : (int)u[0].num_sta,
           tc->expect_num_sta, u.empty() ? -1 : (int)u[0].interval, u.size() >= 2 ? (int)u[1].num_sta : -1);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(void)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/assert above)" : "survived", st);
    return aborted;
}
} /* namespace spl */

void run_all_tests_policy_sync_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; spl::suite[i].test_name != NULL; i++) {
        spl::test_case_t *test = &spl::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        spl::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = spl::test_crash_fork(); if (ok) crashes++; }
        else                           ok = spl::test_one(test);
        spl::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("policy_sync_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
