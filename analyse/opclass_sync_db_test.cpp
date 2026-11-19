/*
 * TEST RUNNER: opclass_sync_db_test
 *
 * Poisoned around the call: for every scripted cell the OCS_GUARD bytes before and after its string buffer and the buffer tail past
 * the string's NUL, so get_string()/strlen() reading outside a cell is reported. The handler's locals (id[128], str[256],
 * ch_str[64][64], token_parts[64], info) are covered by ASan redzones: an ID / list longer than its buffer is reported, a list with
 * 65+ entries trips the assert in get_strings_by_token. PASS = recorded op classes, num_channels, first / last channel, first
 * preference, channel column and second-row channel count match. crash_* cases ABORT on the original code: they run last and UNFORKED
 * so a plain `make` stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "opclass_sync_db.h"

namespace ocs {
static void poison(bool on)
{
    for (int r = 0; r < OCS_ROWS; r++) for (int c = 0; c < OCS_COLS; c++) {
        cell_t *x = &g_rows[r].c[c];
        size_t used = (x->kind == 1 ? strlen(x->s) : 0) + 1;
        if (on) { __asan_poison_memory_region(x->before, OCS_GUARD); __asan_poison_memory_region(x->after, OCS_GUARD); __asan_poison_memory_region(x->s + used, OCS_CELL_SZ - used); }
        else    { __asan_unpoison_memory_region(x->before, OCS_GUARD); __asan_unpoison_memory_region(x->after, OCS_GUARD); __asan_unpoison_memory_region(x->s + used, OCS_CELL_SZ - used); }
    }
}
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    auto &u = dm_op_class_list_t::g_updates;
    int ok = (int)u.size() == tc->expect_updates;
    if (!u.empty()) {
        em_op_class_info_t *i = &u[0];
        if (tc->expect_nch >= 0) ok = ok && (int)i->num_channels == tc->expect_nch;
        if (tc->expect_pref0 >= 0) ok = ok && i->channel_pref[0] == tc->expect_pref0;
        if (tc->expect_chan0 >= 0 && i->num_channels > 0) ok = ok && (int)i->channels[0] == tc->expect_chan0;
        if (tc->expect_chan_last >= 0 && i->num_channels > 0 && i->num_channels <= EM_MAX_CHANNELS_IN_LIST) ok = ok && (int)i->channels[i->num_channels - 1] == tc->expect_chan_last;
        if (tc->expect_channel >= 0) ok = ok && (int)i->channel == tc->expect_channel;
        if (tc->expect_row2_nch >= 0 && u.size() >= 2) ok = ok && (int)u[1].num_channels == tc->expect_row2_nch;
    }
    printf("    updates=%zu (expect %d) num_channels=%d (expect %d) channel=%d row2_nch=%d\n", u.size(), tc->expect_updates, u.empty() ? -1 : (int)u[0].num_channels,
           tc->expect_nch, u.empty() ? -1 : (int)u[0].channel, u.size() >= 2 ? (int)u[1].num_channels : -1);
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
} /* namespace ocs */

void run_all_tests_opclass_sync_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; ocs::suite[i].test_name != NULL; i++) {
        ocs::test_case_t *test = &ocs::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        ocs::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = ocs::test_crash_fork(); if (ok) crashes++; }
        else                           ok = ocs::test_one(test);
        ocs::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("opclass_sync_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
