/*
 * TEST RUNNER: radio_cap_update_db_test
 *
 * Poisoned around the call: RCU_GUARD bytes in front of and behind the radio cap info, so a read of wifi7_cap that runs past the
 * struct is reported; the handler's wifi7_str[256] / mac_str[18] locals are covered by ASan redzones (the hex loop writes past
 * wifi7_str). PASS = return value, number of row calls, length of the wifi7 string (976 hex characters), the first bytes of the
 * pattern, the key and num_op_classes. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make`
 * stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "radio_cap_update_db.h"

namespace rcu {
static void poison(bool on)
{
    void *r[2] = { g_box->before, g_box->after };
    for (int i = 0; i < 2; i++) { if (on) __asan_poison_memory_region(r[i], RCU_GUARD); else __asan_unpoison_memory_region(r[i], RCU_GUARD); }
}
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret && g_calls == tc->expect_calls;
    int len = (int)strlen(g_wifi7);
    if (tc->expect_len >= 0) {
        ok = ok && len == tc->expect_len && g_nop == 7 && !strcmp(g_key, "02:00:00:00:00:01");
        for (int i = 0; ok && i < len; i++) {
            unsigned char b = tc->pattern == 0 ? 0 : tc->pattern == 1 ? (unsigned char)((i / 2) % 251) : 0xFF; char h[3]; snprintf(h, sizeof(h), "%02X", b);
            if (g_wifi7[i] != h[i % 2]) { ok = 0; }
        }
    }
    printf("    ret=%d (expect %d) calls=%d (expect %d) wifi7_len=%d (expect %d) key=%s num_op_classes=%u\n", rc, tc->expect_ret, g_calls, tc->expect_calls, len, tc->expect_len, g_key, g_nop);
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
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan above)" : "survived", st);
    return aborted;
}
} /* namespace rcu */

void run_all_tests_radio_cap_update_db(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; rcu::suite[i].test_name != NULL; i++) {
        rcu::test_case_t *test = &rcu::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        rcu::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = rcu::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = rcu::test_one(test);
        rcu::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("radio_cap_update_db: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
