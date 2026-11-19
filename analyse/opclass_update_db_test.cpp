/*
 * TEST RUNNER: opclass_update_db_test
 *
 * Poisoned around the call: OUD_GUARD bytes in front of and behind the op class info, and the after_channels / after_pref guards right
 * behind channels[64] and channel_pref[64] (stand for the members that follow the arrays in the real struct), so a read of
 * channels[i] / channel_pref[i] with i >= 64 is reported. The handler's locals (mac_str[18], id[128], channels_str[256], pref_str[256],
 * tmp[8]) are covered by ASan redzones. PASS = return value, row-call count, channel entry count, first / last channel and
 * preference string match. clamp_* / rej_* cases ABORTED on the original code: they run last and UNFORKED so a plain `make` stops with
 * the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "opclass_update_db.h"

namespace oud {
static void poison(bool on)
{
    void *regions[4] = { g_box->before, g_box->after, g_box->info.after_channels, g_box->info.after_pref };
    for (int i = 0; i < 4; i++) { if (on) __asan_poison_memory_region(regions[i], OUD_GUARD); else __asan_unpoison_memory_region(regions[i], OUD_GUARD); }
}
static int entries(const char *l) { if (!*l) return 0; int n = 1; for (; *l; l++) if (*l == ',') n++; return n; }
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret && g_calls == tc->expect_calls;
    if (tc->expect_entries >= 0) ok = ok && entries(g_channels) == tc->expect_entries;
    if (tc->expect_first && *g_channels) { char f[32]; snprintf(f, sizeof(f), "%.*s", (int)strcspn(g_channels, ","), g_channels); ok = ok && !strcmp(f, tc->expect_first); }
    if (tc->expect_last && *g_channels) { const char *c = strrchr(g_channels, ','); ok = ok && !strcmp(c ? c + 1 : g_channels, tc->expect_last); }
    if (tc->expect_pref) ok = ok && !strcmp(g_pref, tc->expect_pref);
    printf("    ret=%d (expect %d) calls=%d (expect %d) entries=%d (expect %d) channels_tail=%s pref=%.20s\n", rc, tc->expect_ret, g_calls, tc->expect_calls,
           entries(g_channels), tc->expect_entries, strlen(g_channels) > 12 ? g_channels + strlen(g_channels) - 12 : g_channels, g_pref);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { poison(true); invoke(tc); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}
} /* namespace oud */

void run_all_tests_opclass_update_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; oud::suite[i].test_name != NULL; i++) {
        oud::test_case_t *test = &oud::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        oud::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = oud::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = oud::test_one(test);
        oud::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("opclass_update_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
