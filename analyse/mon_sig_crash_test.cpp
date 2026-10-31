/*
 * TEST RUNNER: mon_sig_crash_test
 *
 * mon_sig_crash's sigstr[64] is internal, so (as with mon_check_process)
 * the explicit poison/unpoison is applied to the array's actual writer,
 * mon_sig_str(): we own a buffer larger than MON_SIGSTR_SZ, poison the
 * tail, and hand mon_sig_str only MON_SIGSTR_SZ -- a write past that size
 * aborts under ASan.
 *
 *   - DIRECT case: poisoned mon_sig_str check over several signals, then a
 *     direct mon_sig_crash(SIGUSR2) (no re-raise). Reaching the end = pass.
 *   - FORK case: reap the child and confirm it died by the expected signal
 *     (an ASan abort in the child would show as SIGABRT instead -> FAIL).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void mon_sig_crash(int signum);
void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);

#define MON_SIGSTR_SZ 64

static char msc_sigbuf[256];

static void poisoned_mon_sig_str_check(int sig)
{
    __asan_poison_memory_region(&msc_sigbuf[MON_SIGSTR_SZ],
                                sizeof(msc_sigbuf) - MON_SIGSTR_SZ);

    mon_sig_str(sig, msc_sigbuf, MON_SIGSTR_SZ);

    __asan_unpoison_memory_region(&msc_sigbuf[MON_SIGSTR_SZ],
                                  sizeof(msc_sigbuf) - MON_SIGSTR_SZ);

    printf("    mon_sig_str(%d) -> \"%s\"\n", sig, msc_sigbuf);
}

/* returns the value to compare against expect_termsig */
int test_mon_sig_crash(const mon_sig_crash_test_case_t *tc)
{
    if (tc->kind == MSC_DIRECT) {
        /* explicit poisoned-buffer check across a range of signals */
        int sigs[] = { SIGTERM, SIGINT, SIGUSR1, SIGHUP, SIGUSR2, SIGRTMIN + 3 };
        for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
            poisoned_mon_sig_str_check(sigs[i]);

        /* direct call is safe only for SIGUSR2 (it does not re-raise) */
        mon_sig_crash(SIGUSR2);
        printf("    mon_sig_crash(SIGUSR2) returned without crashing\n");
        return 0;   /* reached the end = no crash */
    }

    /* FORK: reap the child the constructor left dead, report its term signal */
    int status = 0;
    waitpid(msc_child, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("    child terminated by signal %d\n", WTERMSIG(status));
        return WTERMSIG(status);
    }
    printf("    child exited (status=%d), not by signal\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return -1;
}

void run_all_tests_mon_sig_crash(void)
{
    for (int i = 0; mon_sig_crash_suite[i].test_name != NULL; i++) {
        mon_sig_crash_test_case_t *test = &mon_sig_crash_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_mon_sig_crash_input(test);

        int got = test_mon_sig_crash(test);

        if (got == test->expect_termsig) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect_termsig, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
