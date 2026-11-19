/*
 * TEST RUNNER: create_cac_cap_tlv_test
 *
 * Poisoned around the call:
 *   - CCC_OUT_LEFT bytes in front of the output buffer and CCC_GUARD bytes behind its CCC_OUT_SZ bytes - catches a write
 *     outside the buffer;
 *   - every radio's before_cac[] and after_cac[] (em_radio_cap_info_t members around cac_cap): after_cac[] directly follows
 *     cac_methods[4], so reading cac_methods[4..], op_classes[48..] or channels[16..] of the last entry is reported.
 * sys_cc[3] / buf[8] are stack arrays covered by ASan redzones. PASS = returned length and the first output bytes match.
 * Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan
 * report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "create_cac_cap_tlv.h"

namespace ccc {
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }
static void poison(bool on)
{
    poison_region(out_store, CCC_OUT_LEFT, on);                                         /* in front of the output */
    poison_region(out_store + CCC_OUT_LEFT + CCC_OUT_SZ, CCC_GUARD, on);                /* behind the output */
    if (g_dm) for (int i = 0; i < EM_MAX_BANDS; i++) {
        poison_region(g_dm->m_radio_cap[i].info.before_cac, CCC_GUARD, on);             /* members before cac_cap */
        poison_region(g_dm->m_radio_cap[i].info.after_cac, CCC_GUARD, on);              /* members after cac_cap */
    }
}
static void call_once(void) { poison(true); invoke(); poison(false); }

static int test_one(const test_case_t *tc)
{
    call_once();
    int ok = tc->expect_len < 0 || g_len == tc->expect_len;
    char hex[64] = "";
    size_t n = g_len > 0 ? (size_t)g_len : 0; if (n > 20) n = 20;
    for (size_t i = 0; i < n; i++) sprintf(hex + 2 * i, "%02x", out_store[CCC_OUT_LEFT + i]);
    if (tc->expect_hex) { size_t l = strlen(tc->expect_hex); ok = ok && strncmp(hex, tc->expect_hex, l < 40 ? l : 40) == 0; }
    printf("    len=%d (expect %d) hex=%s%s%s\n", g_len, tc->expect_len, hex, tc->expect_hex ? " expect " : "", tc->expect_hex ? tc->expect_hex : "");
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    (void)tc; fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}
} /* namespace ccc */

void run_all_tests_create_cac_cap_tlv(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; ccc::suite[i].test_name != NULL; i++) {
        ccc::test_case_t *test = &ccc::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        ccc::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = ccc::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = ccc::test_one(test);
        ccc::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("create_cac_cap_tlv: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
