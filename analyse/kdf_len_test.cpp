/*
 * TEST RUNNER: kdf_len_test
 *
 * Poisoned around the call: KDL_GUARD bytes in front of and behind each input buffer (key, label, context, output), every one exactly
 * its length, so a read past the key / label / context or a write past the output buffer is reported; the handler's hash[64] /
 * addr[4] / len[4] locals are covered by ASan redzones. PASS = return value and the output equals an independent HMAC based 802.11
 * KDF-Hash-Length. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops with the report;
 * FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include <vector>
#include "kdf_len.h"

namespace kdl {
static void poison(bool on)
{
    gbuf_t *b[4] = { &g_key, &g_label, &g_ctx, &g_out };
    for (int i = 0; i < 4; i++) {
        void *r[2] = { b[i]->raw, b[i]->p + b[i]->n };
        for (int k = 0; k < 2; k++) { if (on) __asan_poison_memory_region(r[k], KDL_GUARD); else __asan_unpoison_memory_region(r[k], KDL_GUARD); }
    }
}
static std::vector<uint8_t> reference(const test_case_t *tc)
{
    std::vector<uint8_t> out; const EVP_MD *md = algo_of(tc->algo); size_t hl = EVP_MD_size(md), iter = (tc->output_len + hl - 1) / hl;
    uint16_t bits = (uint16_t)(tc->output_len * 8);
    for (size_t i = 1; i <= iter; i++) {
        std::vector<uint8_t> msg = { (uint8_t)(i & 0xFF), (uint8_t)(i >> 8) };
        msg.insert(msg.end(), g_label.p, g_label.p + strlen((char *)g_label.p));
        msg.insert(msg.end(), g_ctx.p, g_ctx.p + g_ctx.n);
        msg.push_back((uint8_t)(bits & 0xFF)); msg.push_back((uint8_t)(bits >> 8));
        uint8_t h[64]; unsigned int n = 0; HMAC(md, g_key.p, (int)tc->key_len, msg.data(), msg.size(), h, &n);
        out.insert(out.end(), h, h + n);
    }
    out.resize(tc->output_len); return out;
}
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret;
    if (tc->check_output) { std::vector<uint8_t> want = reference(tc); ok = ok && g_out.n >= want.size() && !memcmp(g_out.p, want.data(), want.size()); }
    printf("    ret=%d (expect %d) output_len=%zu first_bytes=%02x%02x%02x%02x\n", rc, tc->expect_ret, tc->output_len, g_out.n > 3 ? g_out.p[0] : 0, g_out.n > 3 ? g_out.p[1] : 0, g_out.n > 3 ? g_out.p[2] : 0, g_out.n > 3 ? g_out.p[3] : 0);
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
} /* namespace kdl */

void run_all_tests_kdf_len(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; kdl::suite[i].test_name != NULL; i++) {
        kdl::test_case_t *test = &kdl::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        kdl::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = kdl::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = kdl::test_one(test);
        kdl::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("kdf_len: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
