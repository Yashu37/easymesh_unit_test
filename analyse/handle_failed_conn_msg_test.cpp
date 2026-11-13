/*
 * TEST RUNNER: handle_failed_conn_msg_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (HFC_LEFT) and past its NUL - catches strrchr / strstr /
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
#include "handle_failed_conn_msg.h"

namespace hfc {
extern int g_rc;

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    poison_region(msg_store, HFC_LEFT, on);                                                        /* in front of the message */
    poison_region(msg_store + HFC_LEFT + g_len, sizeof(msg_store) - HFC_LEFT - g_len, on);         /* past its end */
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
    int ok = (g_npub == tc->expect_pub);
    if (tc->has) ok = ok && g_npub >= 1 && strstr(g_pub, tc->has) != NULL;
    if (tc->not_has) ok = ok && strstr(g_pub, tc->not_has) == NULL;
    printf("    published=%d (expect %d) has=%s json=%.150s\n", g_npub, tc->expect_pub,
           tc->has ? (strstr(g_pub, tc->has) ? "found" : "MISSING") : "-", g_npub ? g_pub : "-");
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

} /* namespace hfc */

int hfc::g_rc = 0;

void run_all_tests_handle_failed_conn_msg(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; hfc::suite[i].test_name != NULL; i++) {
        hfc::test_case_t *test = &hfc::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        hfc::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = hfc::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = hfc::test_one(test);      /* a crash case aborts the whole run here */
        hfc::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("handle_failed_conn_msg: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
