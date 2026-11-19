/*
 * TEST RUNNER: sta_sync_db_test
 *
 * Poisoned around the call: for every scripted cell the SSD_GUARD bytes before and after its string buffer and the buffer tail past the
 * string's NUL, so get_string()/strlen()/unhex() reading outside a cell is reported. The handler's mac[18], frame_body[1024] and info
 * locals are covered by ASan redzones: a MAC / frame body column longer than the buffer is reported. PASS = recorded stations, station
 * MAC, first frame body byte and the second-row checks match. crash_* cases ABORT on the original code: they run last and UNFORKED
 * so a plain `make` stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "sta_sync_db.h"

namespace ssd {
static void poison(bool on)
{
    for (int r = 0; r < SSD_ROWS; r++) for (int c = 0; c < SSD_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) { __asan_poison_memory_region(x->before, SSD_GUARD); __asan_poison_memory_region(x->after, SSD_GUARD); __asan_poison_memory_region(x->s + used, SSD_CELL_SZ - used); }
        else    { __asan_unpoison_memory_region(x->before, SSD_GUARD); __asan_unpoison_memory_region(x->after, SSD_GUARD); __asan_unpoison_memory_region(x->s + used, SSD_CELL_SZ - used); }
    }
}
static void mac_str(const unsigned char *b, char *o) { snprintf(o, 18, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]); }
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    auto &u = dm_sta_list_t::g_updates;
    int ok = (int)u.size() == tc->expect_updates;
    char id0[24] = "-", id1[24] = "-";
    if (!u.empty()) mac_str(u[0].id, id0);
    if (u.size() >= 2) mac_str(u[1].id, id1);
    if (tc->expect_id && !u.empty()) ok = ok && !strcmp(id0, tc->expect_id);
    if (tc->expect_b0 >= 0 && !u.empty()) ok = ok && u[0].frame_body[0] == tc->expect_b0;
    if (tc->expect_row2_id_zero && u.size() >= 2) ok = ok && !strcmp(id1, "00:00:00:00:00:00");
    if (tc->expect_row2_b0 >= 0 && u.size() >= 2) ok = ok && u[1].frame_body[0] == tc->expect_row2_b0;
    printf("    updates=%zu (expect %d) id=%s b0=%02x row2_id=%s row2_b0=%02x\n", u.size(), tc->expect_updates, id0, u.empty() ? 0 : u[0].frame_body[0], id1,
           u.size() >= 2 ? u[1].frame_body[0] : 0);
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
} /* namespace ssd */

void run_all_tests_sta_sync_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; ssd::suite[i].test_name != NULL; i++) {
        ssd::test_case_t *test = &ssd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        ssd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = ssd::test_crash_fork(); if (ok) crashes++; }
        else                           ok = ssd::test_one(test);
        ssd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("sta_sync_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
