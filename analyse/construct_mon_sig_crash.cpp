/*
 * TEST CASES / CONSTRUCTOR: construct_mon_sig_crash
 *
 * mon_sig_crash(signum) formats the signal into a local sigstr[64] via
 * mon_sig_str(), then (for every signal except SIGUSR2) raises the signal
 * to re-crash. So:
 *   - MSC_DIRECT : the runner calls mon_sig_crash(SIGUSR2) in-process
 *                  (no re-raise) and also does the poisoned mon_sig_str
 *                  boundary check.
 *   - MSC_FORK   : we fork a child that calls mon_sig_crash(sig); the child
 *                  re-raises and dies by that signal. The parent later
 *                  checks it died by the expected signal -- which also
 *                  proves mon_sig_crash ran the sigstr/mon_sig_str path
 *                  without an ASan abort (that would kill the child by
 *                  SIGABRT instead).
 *
 * We use only signals ASan does not itself intercept (TERM/INT/USR1/HUP),
 * so the delivered signal is the one we expect.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void mon_sig_crash(int signum);

pid_t       msc_child;
const char *msc_case_name;

mon_sig_crash_test_case_t mon_sig_crash_suite[] = {
    /* name            kind         sig        expect_termsig (FORK) / 0 (DIRECT) */
    { "direct_usr2",   MSC_DIRECT,  SIGUSR2,   0  },   /* no re-raise; returns   */
    { "fork_sigterm",  MSC_FORK,    SIGTERM,   SIGTERM },
    { "fork_sigint",   MSC_FORK,    SIGINT,    SIGINT  },
    { "fork_sigusr1",  MSC_FORK,    SIGUSR1,   SIGUSR1 },
    { "fork_sighup",   MSC_FORK,    SIGHUP,    SIGHUP  },

    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_mon_sig_crash_input(const mon_sig_crash_test_case_t *tc)
{
    msc_case_name = tc->test_name;
    msc_child = -1;

    if (tc->kind != MSC_FORK)
        return;

    pid_t pid = fork();
    if (pid == 0) {
        /* ---- child: run the handler; it re-raises tc->sig and dies ---- */
        mon_sig_crash(tc->sig);
        _exit(0);   /* only reached if it somehow did not raise */
    }

    /* ---- parent ---- */
    msc_child = pid;

    /* wait until the child is dead, but leave it reapable for the runner */
    siginfo_t info;
    waitid(P_PID, pid, &info, WEXITED | WNOWAIT);
}
