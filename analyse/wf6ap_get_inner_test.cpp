/*
 * TEST RUNNER: wf6ap_get_inner_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (W6G_LEFT) and past its NUL - catches strrchr / strstr /
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
#include "wf6ap_get_inner.h"

namespace w6g {
extern int g_rc;

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    if (tc->event) {
        size_t used = strlen(name_store + W6G_LEFT) + 1;
        poison_region(name_store, W6G_LEFT, on);                                                   /* in front of event_name */
        poison_region(name_store + W6G_LEFT + used, sizeof(name_store) - W6G_LEFT - used, on);     /* past its NUL */
    }
    for (int i = 0; i < g_ndm; i++) {
        poison_region(g_dm[i]->before, sizeof(g_dm[i]->before), on);                               /* members before m_radio[] */
        poison_region(g_dm[i]->after, sizeof(g_dm[i]->after), on);                                 /* members after m_radio[] */
        for (int r = 0; r < EM_MAX_BANDS; r++)
            poison_region(g_dm[i]->cap[r].info.rest_of_struct, sizeof(g_dm[i]->cap[r].info.rest_of_struct), on);  /* after roles[2] */
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(tc->event ? name_store + W6G_LEFT : NULL, tc->no_pdata);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == tc->expect_rc);
    if (tc->check_val) ok = ok && g_nset >= 1 && !strcmp(g_val, tc->expect_val);
    if (tc->expect_rc != 0) ok = ok && g_nset == 0;
    printf("    rc=%d (expect %d) value=%s%s%s sets=%d\n", g_rc, tc->expect_rc, g_nset ? g_val : "-",
           tc->check_val ? " expect " : "", tc->check_val ? tc->expect_val : "", g_nset);
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

} /* namespace w6g */

int w6g::g_rc = 0;

void run_all_tests_wf6ap_get_inner(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; w6g::suite[i].test_name != NULL; i++) {
        w6g::test_case_t *test = &w6g::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        w6g::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = w6g::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = w6g::test_one(test);      /* a crash case aborts the whole run here */
        w6g::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("wf6ap_get_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
