/*
 * TEST RUNNER: key_unwrap_test
 *
 * Poisoned around the call: AKU_GUARD bytes in front of and behind each buffer (KEK, wrapped key, unwrapped output), every one
 * exactly its length, so a read past the KEK / wrapped key or a write past the unwrapped buffer is reported; the handler's iv[8] and
 * platform_cipher_decrypt's buf[16] / err_buf[256] locals are covered by ASan redzones. PASS = return value and, for a valid key,
 * *unwrapped_len and the unwrapped bytes equal the plaintext; on a failed unwrap *unwrapped_len is untouched. crash_* cases ABORT on
 * the original code: they run last and UNFORKED so a plain `make` stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "key_unwrap.h"

namespace aku {
static void poison(bool on)
{
    gbuf_t *b[3] = { &g_kek, &g_wrapped, &g_out };
    for (int i = 0; i < 3; i++) {
        void *r[2] = { b[i]->raw, b[i]->p + b[i]->n };
        for (int k = 0; k < 2; k++) { if (on) __asan_poison_memory_region(r[k], AKU_GUARD); else __asan_unpoison_memory_region(r[k], AKU_GUARD); }
    }
}
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret;
    if (tc->check_output) ok = ok && g_ulen == tc->plain_len && g_out.n >= tc->plain_len && !memcmp(g_out.p, g_plain.p, tc->plain_len);
    if (tc->expect_ret == 0) ok = ok && g_ulen == 0xDEADBEEF;
    printf("    ret=%d (expect %d) unwrapped_len=%u (plain %u) out_buf=%zu\n", rc, tc->expect_ret, g_ulen, tc->plain_len, g_out.n);
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
} /* namespace aku */

void run_all_tests_key_unwrap(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; aku::suite[i].test_name != NULL; i++) {
        aku::test_case_t *test = &aku::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        aku::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = aku::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = aku::test_one(test);
        aku::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("key_unwrap: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
