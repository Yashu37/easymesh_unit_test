/*
 * TEST RUNNER: policy_update_db_test
 *
 * Poisoned around the call: PUD_GUARD bytes in front of and behind the policy object and the after_sta_mac guard right behind
 * policy->sta_mac[16] (stands for the members that follow the array in the real em_policy_t), so a read of sta_mac[i] with
 * i >= 16 is reported. The handler's locals (key[256], sta_mac_str[18], sta_mac_list_str[1024], dev/radio MAC strings) are covered by
 * ASan redzones. PASS = return value, row-call count, STA entry count and key match. clamp_* / rej_* cases ABORTED on the original
 * code: they run last and UNFORKED so a plain `make` stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "policy_update_db.h"

namespace pud {
static void poison(bool on)
{
    void *regions[3] = { g_box->before, g_box->after, g_box->p.after_sta_mac };
    for (int i = 0; i < 3; i++) { if (on) __asan_poison_memory_region(regions[i], PUD_GUARD); else __asan_unpoison_memory_region(regions[i], PUD_GUARD); }
}
static int entries(const char *l) { if (!*l) return 0; int n = 1; for (; *l; l++) if (*l == ',') n++; return n; }
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret && g_calls == tc->expect_calls;
    if (tc->expect_entries >= 0) ok = ok && entries(g_list) == tc->expect_entries;
    if (tc->expect_key) ok = ok && !strcmp(g_key, tc->expect_key);
    printf("    ret=%d (expect %d) calls=%d (expect %d) entries=%d (expect %d) key=%s\n", rc, tc->expect_ret, g_calls, tc->expect_calls, entries(g_list), tc->expect_entries, g_key);
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
} /* namespace pud */

void run_all_tests_policy_update_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; pud::suite[i].test_name != NULL; i++) {
        pud::test_case_t *test = &pud::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        pud::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = pud::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = pud::test_one(test);
        pud::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("policy_update_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
