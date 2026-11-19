/*
 * TEST RUNNER: ec_b64key_test
 *
 * Poisoned around the call: EKB_GUARD bytes of the input string's own heap buffer right behind its terminator, so a read of the
 * base64 text past its length is reported; the handler's key[1024] stack array is covered by ASan redzones (libcrypto's decode write
 * goes through asan_visible_decode_block, see ec_b64key.h). PASS = a valid key comes back and equals the generated one, every other
 * input returns NULL. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops with the report;
 * FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "ec_b64key.h"

namespace ekb {
static void poison(bool on)
{
    char *g = &g_input[0] + g_input.size() + 1;
    if (g_input.capacity() < g_input.size() + 1 + EKB_GUARD) return;
    if (on) __asan_poison_memory_region(g, EKB_GUARD); else __asan_unpoison_memory_region(g, EKB_GUARD);
}
static int test_one(const test_case_t *tc)
{
    poison(true); SSL_KEY *k = invoke(); poison(false);
    int ok = tc->expect_key ? (k != NULL && g_ref != NULL && EVP_PKEY_eq(k, g_ref) == 1) : (k == NULL);
    printf("    input_len=%zu key=%s (expect %s)\n", g_input.size(), k ? "returned" : "NULL", tc->expect_key ? "returned" : "NULL");
    if (k) EVP_PKEY_free(k);
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
} /* namespace ekb */

void run_all_tests_ec_b64key(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; ekb::suite[i].test_name != NULL; i++) {
        ekb::test_case_t *test = &ekb::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        ekb::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = ekb::test_crash_fork(); if (ok) crashes++; }
        else                           ok = ekb::test_one(test);
        ekb::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("ec_b64key: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
