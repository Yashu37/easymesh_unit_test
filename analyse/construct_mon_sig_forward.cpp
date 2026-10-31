/*
 * TEST CASES / CONSTRUCTOR: construct_mon_sig_forward
 *
 * mon_sig_forward(signum) does nothing unless mon_sig_forward_pid > 0; when
 * set, it formats the signal into a local sigstr[64] (via mon_sig_str) and
 * kill()s that pid. Cases:
 *   - MSF_NOPID   : mon_sig_forward_pid = 0  -> early return (no array use)
 *   - MSF_LIVE    : fork a sleeping child, point mon_sig_forward_pid at it,
 *                   forward a signal -> child is killed by it
 *   - MSF_DEAD    : point mon_sig_forward_pid at a reaped (dead) pid ->
 *                   kill() fails, mon_sig_forward_pid reset to 0
 *
 * The constructor just sets up mon_sig_forward_pid and (for LIVE) the child;
 * the runner performs the forward and checks the outcome. Signals are ones
 * ASan does not intercept.
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

pid_t       msf_child;         /* live child pid (LIVE case) */
const char *msf_case_name;

mon_sig_forward_test_case_t mon_sig_forward_suite[] = {
    /* name              kind        sig       expect (see runner) */
    { "no_pid",          MSF_NOPID,  SIGTERM,  0 },  /* pid<=0: nothing happens */
    { "live_sigterm",    MSF_LIVE,   SIGTERM,  SIGTERM },
    { "live_sigint",     MSF_LIVE,   SIGINT,   SIGINT  },
    { "live_sigusr1",    MSF_LIVE,   SIGUSR1,  SIGUSR1 },
    { "dead_pid",        MSF_DEAD,   SIGTERM,  0 },  /* kill fails -> pid reset to 0 */

    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_mon_sig_forward_input(const mon_sig_forward_test_case_t *tc)
{
    msf_case_name = tc->test_name;
    msf_child = -1;

    if (tc->kind == MSF_NOPID) {
        mon_sig_forward_pid = 0;
        return;
    }

    if (tc->kind == MSF_DEAD) {
        /* make a child, reap it so its pid is dead, then target that pid */
        pid_t pid = fork();
        if (pid == 0) _exit(0);
        int st; waitpid(pid, &st, 0);     /* fully reaped -> pid now dead */
        mon_sig_forward_pid = pid;
        return;
    }

    /* MSF_LIVE: a child that waits to be killed */
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) pause();
        _exit(0);
    }
    usleep(10 * 1000);                     /* let it reach pause() */
    msf_child = pid;
    mon_sig_forward_pid = pid;
}
