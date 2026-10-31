/*
 * TEST RUNNER: mon_sig_forward_test
 *
 * As with the other monitor functions, mon_sig_forward's sigstr[64] is
 * internal, so the explicit poison/unpoison is applied to the array's
 * writer, mon_sig_str(): own a buffer larger than MON_SIGSTR_SZ, poison the
 * tail, hand mon_sig_str only MON_SIGSTR_SZ -> a write past that aborts.
 *
 * Then per case:
 *   - NOPID: call mon_sig_forward; pid stays 0, nothing killed.
 *   - LIVE : forward the signal, confirm the child died by that signal.
 *   - DEAD : forward to a dead pid, confirm mon_sig_forward_pid got reset.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void mon_sig_forward(int signum);
void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);

#define MON_SIGSTR_SZ 64

static char msf_sigbuf[256];

static void poisoned_mon_sig_str_check(int sig)
{
    __asan_poison_memory_region(&msf_sigbuf[MON_SIGSTR_SZ],
                                sizeof(msf_sigbuf) - MON_SIGSTR_SZ);
    mon_sig_str(sig, msf_sigbuf, MON_SIGSTR_SZ);
    __asan_unpoison_memory_region(&msf_sigbuf[MON_SIGSTR_SZ],
                                  sizeof(msf_sigbuf) - MON_SIGSTR_SZ);
    printf("    mon_sig_str(%d) -> \"%s\"\n", sig, msf_sigbuf);
}

/* returns a value to compare against tc->expect */
int test_mon_sig_forward(const mon_sig_forward_test_case_t *tc)
{
    /* explicit poisoned-buffer check of the array writer */
    poisoned_mon_sig_str_check(tc->sig);

    mon_sig_forward(tc->sig);

    if (tc->kind == MSF_LIVE) {
        int status = 0;
        waitpid(msf_child, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("    child terminated by signal %d\n", WTERMSIG(status));
            return WTERMSIG(status);
        }
        printf("    child did not die by signal\n");
        return -1;
    }

    /* NOPID and DEAD: both should leave mon_sig_forward_pid == 0 */
    printf("    mon_sig_forward_pid now = %d\n", (int)mon_sig_forward_pid);
    return (mon_sig_forward_pid == 0) ? 0 : -1;
}

void run_all_tests_mon_sig_forward(void)
{
    for (int i = 0; mon_sig_forward_suite[i].test_name != NULL; i++) {
        mon_sig_forward_test_case_t *test = &mon_sig_forward_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_mon_sig_forward_input(test);

        int got = test_mon_sig_forward(test);

        if (got == test->expect) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
