/*
 * TEST RUNNER: affsta_get_inner_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (AFG_LEFT) and past its NUL - catches strrchr / strstr /
 *     name += sizeof(DATAELEMS_NETWORK) reading outside the name;
 *   - dm->before[] / dm->between[] / dm->after[], the members around dm->m_ap_mld[] and dm->m_assoc_sta_mld[];
 *   - every AP MLD's and STA MLD's rest_of_struct[] - rest_of_struct[] of a STA MLD sits right after
 *     affiliated_sta[EM_MAX_AP_MLD], so it catches smi->affiliated_sta[idx - 1] with idx > 64 when the unsigned char
 *     num_affiliated_sta is 65..255.
 * The local array (instance[32]) is guarded by an ASan redzone, the dm and STA objects are heap allocated. PASS = return
 * code matches and the value recorded by raw_data_set matches. Cases named crash_* ABORT on the original handler: they
 * run last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "affsta_get_inner.h"

namespace afg {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    if (tc->event) {
        size_t used = strlen(name_store + AFG_LEFT) + 1;
        poison_region(name_store, AFG_LEFT, on);                                                   /* in front of event_name */
        poison_region(name_store + AFG_LEFT + used, sizeof(name_store) - AFG_LEFT - used, on);     /* past its NUL */
    }
    if (g_dm) {
        poison_region(g_dm->before, sizeof(g_dm->before), on);                                     /* members before m_ap_mld[] */
        poison_region(g_dm->between, sizeof(g_dm->between), on);                                   /* members between the two arrays */
        poison_region(g_dm->after, sizeof(g_dm->after), on);                                       /* members after m_assoc_sta_mld[] */
        for (int a2 = 0; a2 < EM_MAX_AP_MLD; a2++)
            poison_region(g_dm->m_ap_mld[a2].info.rest_of_struct, sizeof(g_dm->m_ap_mld[a2].info.rest_of_struct), on);
        for (int s = 0; s < EM_MAX_ASSOC_STA_MLD; s++)
            poison_region(g_dm->m_assoc_sta_mld[s].info.rest_of_struct, sizeof(g_dm->m_assoc_sta_mld[s].info.rest_of_struct), on);
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(tc->event ? name_store + AFG_LEFT : NULL, tc->no_pdata);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == tc->expect_rc);
    if (tc->expect_val) ok = ok && g_nset >= 1 && !strcmp(g_val, tc->expect_val);
    if (tc->expect_rc != 0) ok = ok && g_nset == 0;
    printf("    rc=%d (expect %d) value=%.40s%s%s sets=%d\n", g_rc, tc->expect_rc, g_nset ? g_val : "-",
           tc->expect_val ? " expect " : "", tc->expect_val ? tc->expect_val : "", g_nset);
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

} /* namespace afg */

int afg::g_rc = 0;

void run_all_tests_affsta_get_inner(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; afg::suite[i].test_name != NULL; i++) {
        afg::test_case_t *test = &afg::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        afg::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = afg::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = afg::test_one(test);      /* a crash case aborts the whole run here */
        afg::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("affsta_get_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
