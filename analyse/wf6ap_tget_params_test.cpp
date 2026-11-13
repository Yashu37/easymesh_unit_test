/*
 * TEST RUNNER: wf6ap_tget_params_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (WTP_LEFT) and past its NUL - catches strrchr / strstr /
 *     name += sizeof(DATAELEMS_NETWORK) reading outside the name;
 *   - dm->before[] / dm->after[], the members in front of and after dm->m_radio[EM_MAX_BANDS] -
 *     catches dm->m_radio[radio_instance - 1] with radio_instance 0, > 3, negative or huge;
 *   - every radio cap's rest_of_struct, the fields after wifi6_cap.roles[MAP_AP_ROLE_MAX] -
 *     catches rci->wifi6_cap.roles[i] with num_role > 2.
 * The local arrays (instance[32], mcsnss_str[256], temp[32]) are guarded by ASan redzones, the dm
 * objects are heap allocated one by one. PASS = return code matches and the value recorded by
 * raw_data_set matches. Cases named crash_* are expected to abort: they run last and UNFORKED so a
 * plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "wf6ap_tget_params.h"

namespace wtp {
extern int g_rc;

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

extern char root_store[];

static void poison(const test_case_t *tc, bool on)
{
    size_t used = strlen(root_store + WTP_ROOT_LEFT) + 1;
    poison_region(root_store, WTP_ROOT_LEFT, on);                                                  /* in front of root */
    poison_region(root_store + WTP_ROOT_LEFT + used, sizeof(root_store) - WTP_ROOT_LEFT - used, on); /* past its NUL */
    if (g_dm)
        poison_region(g_dm->cap.info.rest_of_struct, sizeof(g_dm->cap.info.rest_of_struct), on);   /* after roles[2] */
    (void)tc;
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(root_store + WTP_ROOT_LEFT, tc->other_radio);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == 0);
    if (tc->expect_roles >= 0) ok = ok && g_roles == tc->expect_roles;
    if (tc->has) ok = ok && strstr(g_rec, tc->has) != NULL;
    if (tc->not_has) ok = ok && strstr(g_rec, tc->not_has) == NULL;
    printf("    rc=%d roles=%d (expect %d) has=%s%s%s\n", g_rc, g_roles, tc->expect_roles,
           tc->has ? (strstr(g_rec, tc->has) ? "found" : "MISSING") : "-",
           tc->not_has ? " not_has=" : "", tc->not_has ? (strstr(g_rec, tc->not_has) ? "PRESENT" : "absent") : "");
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

} /* namespace wtp */

int wtp::g_rc = 0;

void run_all_tests_wf6ap_tget_params(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; wtp::suite[i].test_name != NULL; i++) {
        wtp::test_case_t *test = &wtp::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        wtp::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = wtp::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = wtp::test_one(test);      /* a crash case aborts the whole run here */
        wtp::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("wf6ap_tget_params: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
