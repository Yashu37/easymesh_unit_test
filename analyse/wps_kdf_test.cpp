/*
 * TEST RUNNER: wps_kdf_test
 *
 * Poisoned around the call: WKD_GUARD bytes in front of and behind each input buffer (key 32 bytes, label_prefix, label, result),
 * every one exactly its length, so a read past the key / prefix / label or a write past the result buffer is reported; the handler's
 * i_buf[4] / key_bits[4] / addr[4] / len[4] / hash[32] locals are covered by ASan redzones. PASS = return value and the output equals
 * an independent HMAC-SHA256 based WPS KDF. crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make`
 * stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include <vector>
#include "wps_kdf.h"

namespace wkd {
static void poison(bool on)
{
    gbuf_t *b[4] = { &g_key, &g_prefix, &g_label, &g_res };
    for (int i = 0; i < 4; i++) {
        void *r[2] = { b[i]->raw, b[i]->p + b[i]->n };
        for (int k = 0; k < 2; k++) { if (on) __asan_poison_memory_region(r[k], WKD_GUARD); else __asan_unpoison_memory_region(r[k], WKD_GUARD); }
    }
}
static std::vector<uint8_t> reference(const test_case_t *tc)
{
    std::vector<uint8_t> out; uint32_t bits = tc->res_len * 8, iter = (tc->res_len + 31) / 32;
    for (uint32_t i = 1; i <= iter; i++) {
        std::vector<uint8_t> msg = { (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i };
        msg.insert(msg.end(), g_prefix.p, g_prefix.p + g_prefix.n);
        msg.insert(msg.end(), g_label.p, g_label.p + strlen((char *)g_label.p));
        uint8_t b4[4] = { (uint8_t)(bits >> 24), (uint8_t)(bits >> 16), (uint8_t)(bits >> 8), (uint8_t)bits }; msg.insert(msg.end(), b4, b4 + 4);
        uint8_t h[32]; unsigned int hl = 0; HMAC(EVP_sha256(), g_key.p, 32, msg.data(), msg.size(), h, &hl);
        out.insert(out.end(), h, h + 32);
    }
    out.resize(tc->res_len); return out;
}
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret;
    if (tc->check_output) { std::vector<uint8_t> want = reference(tc); ok = ok && g_res.n >= want.size() && !memcmp(g_res.p, want.data(), want.size()); }
    printf("    ret=%d (expect %d) res_len=%u first_bytes=%02x%02x%02x%02x\n", rc, tc->expect_ret, tc->res_len, g_res.n > 3 ? g_res.p[0] : 0, g_res.n > 3 ? g_res.p[1] : 0, g_res.n > 3 ? g_res.p[2] : 0, g_res.n > 3 ? g_res.p[3] : 0);
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
} /* namespace wkd */

void run_all_tests_wps_kdf(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; wkd::suite[i].test_name != NULL; i++) {
        wkd::test_case_t *test = &wkd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        wkd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = wkd::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = wkd::test_one(test);
        wkd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("wps_kdf: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
