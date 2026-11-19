/*
 * TEST RUNNER: hash_hex_test
 *
 * Poisoned around the call: HHX_GUARD bytes in front of and behind the hash buffer (which is exactly len bytes), so a read past the
 * hash is reported; the handler's output[2 * len + 1] stack array is covered by ASan redzones. PASS = the returned string equals an
 * independently built hex string (empty for a NULL hash). crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops
 * with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "hash_hex.h"

namespace hhx {
static void poison(bool on)
{
    void *r[2] = { g_raw, g_hash + g_len };
    for (int i = 0; i < 2; i++) { if (on) __asan_poison_memory_region(r[i], HHX_GUARD); else __asan_unpoison_memory_region(r[i], HHX_GUARD); }
}
static int test_one(const test_case_t *tc)
{
    poison(true); std::string s = invoke(tc); poison(false);
    std::string want; static const char *d = "0123456789abcdef";
    for (size_t i = 0; !tc->null_hash && i < g_len; i++) { want += d[g_hash[i] >> 4]; want += d[g_hash[i] & 15]; }
    int ok = s == want;
    printf("    len=%zu result_len=%zu (expect %zu) first=%.16s\n", g_len, s.size(), want.size(), s.c_str());
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
} /* namespace hhx */

void run_all_tests_hash_hex(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; hhx::suite[i].test_name != NULL; i++) {
        hhx::test_case_t *test = &hhx::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        hhx::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = hhx::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = hhx::test_one(test);
        hhx::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("hash_hex: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
