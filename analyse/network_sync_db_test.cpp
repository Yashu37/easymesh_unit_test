/*
 * TEST RUNNER: network_sync_db_test
 *
 * Poisoned around the call: for every scripted cell the NSD_GUARD bytes before and after its string buffer and the buffer tail past
 * the string's NUL, so get_string()/strlen() reading outside a cell is reported. The handler's locals (mac[18], date_time[64], info)
 * are covered by ASan redzones: a MAC column longer than 17 characters, or an ID column that runs past the whole info struct, is
 * reported. PASS = recorded networks, MACs and timestamp match. crash_* cases ABORT on the original code: they run last and
 * UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "network_sync_db.h"

namespace nsd {
static void poison(bool on)
{
    for (int r = 0; r < NSD_ROWS; r++) for (int c = 0; c < NSD_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) { __asan_poison_memory_region(x->before, NSD_GUARD); __asan_poison_memory_region(x->after, NSD_GUARD); __asan_poison_memory_region(x->s + used, NSD_CELL_SZ - used); }
        else    { __asan_unpoison_memory_region(x->before, NSD_GUARD); __asan_unpoison_memory_region(x->after, NSD_GUARD); __asan_unpoison_memory_region(x->s + used, NSD_CELL_SZ - used); }
    }
}
static void mac_str(const unsigned char *b, char *o) { snprintf(o, 18, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]); }
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    auto &u = dm_network_list_t::g_updates;
    int ok = (int)u.size() == tc->expect_updates;
    char m[24] = "-", c[24] = "-";
    if (!u.empty()) { mac_str(u[0].ctrl_id.mac, m); mac_str(u[0].colocated_agent_id.mac, c); }
    if (tc->expect_ctrl && !u.empty()) ok = ok && !strcmp(m, tc->expect_ctrl);
    if (tc->expect_colo && !u.empty()) ok = ok && !strcmp(c, tc->expect_colo);
    int ts_ok = !u.empty() && strlen(u[0].timestamp) == 20 && u[0].timestamp[0] >= '0' && u[0].timestamp[0] <= '9';
    if (tc->expect_ts_intact) ok = ok && ts_ok;
    if (tc->expect_row2_ctrl_zero && u.size() >= 2) { char z[24]; mac_str(u[1].ctrl_id.mac, z); ok = ok && !strcmp(z, "00:00:00:00:00:00"); }
    char r2[24] = "-"; if (u.size() >= 2) mac_str(u[1].ctrl_id.mac, r2);
    printf("    updates=%zu (expect %d) ctrl=%s colo=%s timestamp_ok=%d row2_ctrl=%s\n", u.size(), tc->expect_updates, m, c, ts_ok, r2);
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
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan above)" : "survived", st);
    return aborted;
}
} /* namespace nsd */

void run_all_tests_network_sync_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; nsd::suite[i].test_name != NULL; i++) {
        nsd::test_case_t *test = &nsd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        nsd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = nsd::test_crash_fork(); if (ok) crashes++; }
        else                           ok = nsd::test_one(test);
        nsd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("network_sync_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
