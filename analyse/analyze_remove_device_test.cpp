/*
 * TEST RUNNER: analyze_remove_device_test
 *
 * Poisoned around the call:
 *   - the event's subdoc.buff past its NUL (the JSON text) and the members after the event's params
 *     (guard) - catches reads past the subdoc;
 *   - pcmd[16] onward (ARD_PCMD_EXTRA slots past the caller's EM_MAX_CMD array) - catches the handler
 *     writing one command per device to delete past the caller's pcmd[16].
 * The local arrays dev_mac_to_keep[32] and devices_to_delete[32] are guarded by ASan stack redzones. PASS =
 * the number of commands matches and the recorded removed-device list matches. Cases named crash_* are
 * expected to abort: they run last and UNFORKED so a plain `make` stops with the ASan report;
 * FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "analyze_remove_device.h"

namespace ard {
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
    poison_region(from, (size_t)((evt_buf + ARD_EVT_SZ) - from), on);                              /* subdoc.buff past its NUL */
    poison_region(evt->guard, sizeof(evt->guard), on);                                             /* members after params */
    poison_region(&pcmd_buf[ARD_MAXCMD], ARD_PCMD_EXTRA * sizeof(void *), on);                     /* pcmd[16..] */
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
    int ok = (g_num == tc->expect_num) && (g_live == 0);   /* every command built was either returned and deleted, or deleted by the handler */
    if (tc->has) ok = ok && g_num >= 1 && strstr(g_sum, tc->has) != NULL;
    if (tc->not_has) ok = ok && strstr(g_sum, tc->not_has) == NULL;
    printf("    ret=%d (expect %d) has=%s sum=%.120s\n", g_num, tc->expect_num,
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

} /* namespace ard */

int ard::g_rc = 0;

void run_all_tests_analyze_remove_device(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; ard::suite[i].test_name != NULL; i++) {
        ard::test_case_t *test = &ard::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        ard::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = ard::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = ard::test_one(test);      /* a crash case aborts the whole run here */
        ard::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("analyze_remove_device: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
