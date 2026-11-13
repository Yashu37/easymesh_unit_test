/*
 * TEST RUNNER: analyze_unassoc_sta_metrics_query_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (UAQ_LEFT) and past its NUL - catches strrchr / strstr /
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
#include "analyze_unassoc_sta_metrics_query.h"

namespace uaq {
extern int g_rc;

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    em_bus_event_t *evt = (em_bus_event_t *)evt_buf;
    char *buff = evt->u.subdoc.buff;
    char *from = buff + strlen(buff) + 1;
    poison_region(from, (size_t)((evt_buf + UAQ_EVT_SZ) - from), on);                              /* subdoc.buff past its NUL */
    poison_region(evt->guard, sizeof(evt->guard), on);                                             /* members after params */
    poison_region(&pcmd_buf[UAQ_MAXCMD], UAQ_PCMD_EXTRA * sizeof(void *), on);                     /* pcmd[16..] */
    (void)tc;
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    invoke();
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_num == tc->expect_num);
    if (tc->has) ok = ok && g_num >= 1 && strstr(g_sum, tc->has) != NULL;
    if (tc->not_has) ok = ok && strstr(g_sum, tc->not_has) == NULL;
    printf("    ret=%d (expect %d) has=%s sum=%.160s\n", g_num, tc->expect_num,
           tc->has ? (strstr(g_sum, tc->has) ? "found" : "MISSING") : "-", g_num ? g_sum : "-");
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

} /* namespace uaq */

int uaq::g_rc = 0;

void run_all_tests_analyze_unassoc_sta_metrics_query(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; uaq::suite[i].test_name != NULL; i++) {
        uaq::test_case_t *test = &uaq::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        uaq::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = uaq::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = uaq::test_one(test);      /* a crash case aborts the whole run here */
        uaq::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("analyze_unassoc_sta_metrics_query: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
