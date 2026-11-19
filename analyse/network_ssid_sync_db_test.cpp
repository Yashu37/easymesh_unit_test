/*
 * TEST RUNNER: network_ssid_sync_db_test
 *
 * Poisoned around the call: for every scripted cell the NSS_GUARD bytes before and after its string buffer and the buffer tail past
 * the string's NUL, so get_string()/strlen() reading outside a cell is reported. The handler's locals (mac[18], str[128],
 * token_parts[10], haul_type[10][32], info) are covered by ASan redzones: a value longer than its buffer is reported, a list with
 * too many entries trips the assert in get_strings_by_token. PASS = recorded networks, num_bands / num_akms / num_hauls and the
 * first two haul types match. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops with the
 * report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "network_ssid_sync_db.h"

namespace nss {
static void poison(bool on)
{
    for (int r = 0; r < NSS_ROWS; r++) for (int c = 0; c < NSS_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) { __asan_poison_memory_region(x->before, NSS_GUARD); __asan_poison_memory_region(x->after, NSS_GUARD); __asan_poison_memory_region(x->s + used, NSS_CELL_SZ - used); }
        else    { __asan_unpoison_memory_region(x->before, NSS_GUARD); __asan_unpoison_memory_region(x->after, NSS_GUARD); __asan_unpoison_memory_region(x->s + used, NSS_CELL_SZ - used); }
    }
}
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    auto &u = dm_network_ssid_list_t::g_updates;
    int ok = (int)u.size() == tc->expect_updates;
    if (!u.empty()) {
        if (tc->expect_nb >= 0) ok = ok && u[0].num_bands == tc->expect_nb;
        if (tc->expect_na >= 0) ok = ok && u[0].num_akms == tc->expect_na;
        if (tc->expect_nh >= 0) ok = ok && u[0].num_hauls == tc->expect_nh;
        if (tc->expect_h0 >= 0) ok = ok && (int)u[0].haul_type[0] == tc->expect_h0;
        if (tc->expect_h1 >= 0) ok = ok && (int)u[0].haul_type[1] == tc->expect_h1;
    }
    printf("    updates=%zu (expect %d) bands=%d akms=%d hauls=%d h0=%d h1=%d\n", u.size(), tc->expect_updates, u.empty() ? -1 : u[0].num_bands,
           u.empty() ? -1 : u[0].num_akms, u.empty() ? -1 : u[0].num_hauls, u.empty() ? -1 : (int)u[0].haul_type[0], u.empty() ? -1 : (int)u[0].haul_type[1]);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(void)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { poison(true); invoke(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/assert above)" : "survived", st);
    return aborted;
}
} /* namespace nss */

void run_all_tests_network_ssid_sync_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; nss::suite[i].test_name != NULL; i++) {
        nss::test_case_t *test = &nss::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        nss::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = nss::test_crash_fork(); if (ok) crashes++; }
        else                           ok = nss::test_one(test);
        nss::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("network_ssid_sync_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
