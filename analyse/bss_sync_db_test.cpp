/*
 * TEST RUNNER: bss_sync_db_test
 *
 * Poisoned around the call: for every scripted cell the BSD_GUARD bytes before and after its string buffer and the buffer tail past the
 * string's NUL, so get_string()/strlen() reading outside a cell is reported. The handler's locals (mac[18], str[128], token_parts[10],
 * info) are covered by ASan redzones: an ID / AKM list longer than str[128] or a MAC longer than mac[18] is reported, an AKM list with
 * 11+ entries trips the assert in get_strings_by_token. PASS = recorded BSSs, haul type, BSSID, SSID, AKM counts, untouched timestamp and
 * second-row BSSID match. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops with the
 * report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "bss_sync_db.h"

namespace bsd {
static void poison(bool on)
{
    for (int r = 0; r < BSD_ROWS; r++) for (int c = 0; c < BSD_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) { __asan_poison_memory_region(x->before, BSD_GUARD); __asan_poison_memory_region(x->after, BSD_GUARD); __asan_poison_memory_region(x->s + used, BSD_CELL_SZ - used); }
        else    { __asan_unpoison_memory_region(x->before, BSD_GUARD); __asan_unpoison_memory_region(x->after, BSD_GUARD); __asan_unpoison_memory_region(x->s + used, BSD_CELL_SZ - used); }
    }
}
static void mac_str(const unsigned char *b, char *o) { snprintf(o, 18, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]); }
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    auto &u = dm_bss_list_t::g_updates;
    int ok = (int)u.size() == tc->expect_updates;
    char b0[24] = "-", b1[24] = "-";
    if (!u.empty()) mac_str(u[0].bssid.mac, b0);
    if (u.size() >= 2) mac_str(u[1].bssid.mac, b1);
    if (!u.empty()) {
        if (tc->expect_haul >= 0) ok = ok && u[0].id.haul_type == tc->expect_haul;
        if (tc->expect_bssid) ok = ok && !strcmp(b0, tc->expect_bssid);
        if (tc->expect_ssid) ok = ok && !strncmp(u[0].ssid, tc->expect_ssid, sizeof(u[0].ssid));
        if (tc->expect_nfh >= 0) ok = ok && u[0].num_fronthaul_akms == tc->expect_nfh;
        if (tc->expect_nbh >= 0) ok = ok && u[0].num_backhaul_akms == tc->expect_nbh;
        if (tc->expect_ts_intact) ok = ok && u[0].timestamp[0] == 0;
    }
    if (tc->expect_row2_bssid_zero && u.size() >= 2) ok = ok && !strcmp(b1, "00:00:00:00:00:00");
    printf("    updates=%zu (expect %d) haul=%d bssid=%s fh=%d bh=%d timestamp0=%02x row2_bssid=%s\n", u.size(), tc->expect_updates, u.empty() ? -1 : u[0].id.haul_type, b0,
           u.empty() ? -1 : u[0].num_fronthaul_akms, u.empty() ? -1 : u[0].num_backhaul_akms, u.empty() ? 0 : (unsigned char)u[0].timestamp[0], b1);
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
} /* namespace bsd */

void run_all_tests_bss_sync_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; bsd::suite[i].test_name != NULL; i++) {
        bsd::test_case_t *test = &bsd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        bsd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = bsd::test_crash_fork(); if (ok) crashes++; }
        else                           ok = bsd::test_one(test);
        bsd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("bss_sync_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
