/*
 * TEST RUNNER: ssid_tget_inner_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (STI_LEFT) and past its NUL - catches event_name[strlen - 1]
 *     on an empty name (reads the byte in front);
 *   - dm->before[] / dm->after[], the members in front of and after dm->m_network_ssid[EM_MAX_NET_SSIDS] -
 *     catches the loop running to the raw m_num_net_ssids when it is above 5;
 *   - every SSID entry's id[] and pass_phrase[] - the handler must never read them (the pass phrase must not
 *     be exported).
 * val_str[1024] is a local array guarded by an ASan redzone. PASS = return code, the number of SSID
 * properties and the recorded lines match. Cases named crash_* ABORT on the original function: they run
 * last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "ssid_tget_inner.h"

namespace sti {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    if (tc->event) {
        size_t used = strlen(name_store + STI_LEFT) + 1;
        poison_region(name_store, STI_LEFT, on);                                                   /* in front of event_name */
        poison_region(name_store + STI_LEFT + used, sizeof(name_store) - STI_LEFT - used, on);     /* past its NUL */
    }
    if (g_dm) {
        poison_region(g_dm->before, sizeof(g_dm->before), on);                                     /* members before m_network_ssid[] */
        poison_region(g_dm->after, sizeof(g_dm->after), on);                                       /* members after m_network_ssid[] */
        for (int r = 0; r < EM_MAX_NET_SSIDS; r++) {
            poison_region(g_dm->m_network_ssid[r].info.id, sizeof(g_dm->m_network_ssid[r].info.id), on);                   /* never read */
            poison_region(g_dm->m_network_ssid[r].info.pass_phrase, sizeof(g_dm->m_network_ssid[r].info.pass_phrase), on); /* never read */
        }
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(tc->event ? name_store + STI_LEFT : NULL, tc->no_pdata);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == tc->expect_rc);
    if (tc->expect_ids >= 0) ok = ok && g_ids == tc->expect_ids;
    if (tc->has) ok = ok && strstr(g_rec, tc->has) != NULL;
    if (tc->not_has) ok = ok && strstr(g_rec, tc->not_has) == NULL;
    if (tc->expect_rc != 0) ok = ok && g_nset == 0;
    printf("    rc=%d (expect %d) ssids=%d (expect %d) sets=%d\n", g_rc, tc->expect_rc, g_ids, tc->expect_ids, g_nset);
    if (!ok) printf("    record:\n%.600s\n", g_rec);
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

} /* namespace sti */

int sti::g_rc = 0;

void run_all_tests_ssid_tget_inner(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; sti::suite[i].test_name != NULL; i++) {
        sti::test_case_t *test = &sti::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        sti::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = sti::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = sti::test_one(test);      /* a crash case aborts the whole run here */
        sti::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("ssid_tget_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
