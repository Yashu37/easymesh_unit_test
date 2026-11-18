/*
 * TEST RUNNER: get_sta_ht_caps_str_test
 *
 * Poisoned around the call:
 *   - the bytes of ht_cap[128] past the string's NUL, and the members before / after the array
 *     (sta_ht_t.before / after) - catches strlen() / unhex() reading outside the string, e.g. a ht_cap
 *     of 128 non-NUL bytes;
 *   - the output buffer past buf_len (the rest of buf_store, GSH_GUARD bytes after caps_str[32]) -
 *     catches a write past the length the caller passed.
 * The local arrays ie[32] are guarded by ASan stack redzones. PASS = the function returns
 * its buf argument and the text written matches the expected one. The case crash_* is expected to abort:
 * it runs last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "get_sta_ht_caps_str.h"

namespace gsh {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    poison_region(g_sta.before, sizeof(g_sta.before), on);                                         /* members in front of ht_cap */
    poison_region(g_sta.after, sizeof(g_sta.after), on);                                           /* members after ht_cap */
    if (tc->gen != 3 && tc->gen != 2) {
        size_t used = strnlen(g_sta.ht_cap, sizeof(g_sta.ht_cap)) + 1;
        if (used < sizeof(g_sta.ht_cap))
            poison_region(g_sta.ht_cap + used, sizeof(g_sta.ht_cap) - used, on);                 /* past the NUL, inside the array */
    }
    poison_region(buf_store + tc->buf_len, sizeof(buf_store) - tc->buf_len, on);                   /* output past buf_len */
}

static const char *g_out = NULL;
static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_out = invoke((char *)g_in, buf_store, tc->buf_len);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_out == buf_store) && strcmp(buf_store, g_expect) == 0;
    printf("    out=\"%.40s\" expect=\"%.40s\"\n", g_out == buf_store ? buf_store : "(not buf)", g_expect);
    return ok;
}

static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(tc); _exit(0); }
    int st = 0;
    waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}

} /* namespace gsh */

void run_all_tests_get_sta_ht_caps_str(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; gsh::suite[i].test_name != NULL; i++) {
        gsh::test_case_t *test = &gsh::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        gsh::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = gsh::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = gsh::test_one(test);      /* a crash case aborts the whole run here */
        gsh::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("get_sta_ht_caps_str: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
