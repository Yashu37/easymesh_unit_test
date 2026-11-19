/*
 * TEST RUNNER: string_to_macbytes_test
 *
 * Poisoned around the call:
 *   - the bytes in front of key (STM_LEFT) and past its NUL - catches strlen / sscanf reading outside the key;
 *   - STM_GUARD bytes before and after bmac[6] - catches a write outside the 6 output bytes.
 * The local array mac[6] is covered by an ASan redzone. The stack is dirtied with 0xAB first (dirty_stack in the
 * handler file) so an uninitialised mac[] is a known value. PASS = bmac equals expect_mac. Cases named crash_* ABORT on the
 * original handler: they run last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "string_to_macbytes.h"

namespace stm {
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }

static void poison(const test_case_t *tc, bool on)
{
    if (tc->key) {
        size_t used = strlen(key_store + STM_LEFT) + 1;
        poison_region(key_store, STM_LEFT, on);                                                  /* in front of key */
        poison_region(key_store + STM_LEFT + used, sizeof(key_store) - STM_LEFT - used, on);     /* past its NUL */
    }
    poison_region(bmac_store, STM_GUARD, on);                                                    /* before bmac */
    poison_region(bmac_store + STM_GUARD + 6, STM_GUARD, on);                                    /* after bmac */
}
static void call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    invoke(tc);
    poison(tc, false);                                                   /* UNPOISON */
}
static int test_one(const test_case_t *tc)
{
    call_once(tc);
    char got[24];
    unsigned char *b = bmac_store + STM_GUARD;
    snprintf(got, sizeof(got), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    int ok = tc->expect_mac == NULL || !strcmp(got, tc->expect_mac);
    printf("    bmac=%s (expect %s)\n", got, tc->expect_mac ? tc->expect_mac : "-");
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(tc); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}
} /* namespace stm */

void run_all_tests_string_to_macbytes(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; stm::suite[i].test_name != NULL; i++) {
        stm::test_case_t *test = &stm::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        stm::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = stm::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = stm::test_one(test);
        stm::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("string_to_macbytes: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
