/*
 * TEST CASES / CONSTRUCTOR: construct_mon_check_process
 *
 * mon_check_process(child, &status) calls waitpid(WNOHANG) and, when the
 * child died from a signal, formats the signal into a local sigstr[64] via
 * mon_sig_str() (which also uses a local sig_default[16] for unknown
 * signals). To drive every path we fork a real child per case:
 *   - MONCP_EXIT   : child _exit(param)            -> WIFEXITED
 *   - MONCP_SIGNAL : parent kills child with param -> WIFSIGNALED
 *                    (param < 0 => a realtime signal, which hits
 *                     mon_sig_str()'s default/sig_default[16] path)
 *   - MONCP_ALIVE  : child sleeps; still running when checked
 *
 * We avoid SEGV/ABRT/BUS/ILL/FPE here because ASan installs its own
 * handlers for those in the (instrumented) child, which would change the
 * delivered signal. The sigstr/sig_default arrays are exercised the same
 * way by any signal.
 *
 * For the terminated cases we waitid(..., WNOWAIT) so the child is known
 * dead but still reapable by mon_check_process's own waitpid().
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

pid_t       moncp_child;
const char *moncp_case_name;

mon_cp_test_case_t mon_check_process_suite[] = {
    /* name          kind           param           exp_ret  exp_status */
    { "exit_0",       MONCP_EXIT,    0,               0,       0  },
    { "exit_42",      MONCP_EXIT,    42,              0,       42 },
    { "sig_term",     MONCP_SIGNAL,  SIGTERM,         0,       0  },  /* non-fatal branch */
    { "sig_int",      MONCP_SIGNAL,  SIGINT,          0,       0  },  /* non-fatal branch */
    { "sig_kill",     MONCP_SIGNAL,  SIGKILL,         0,       64 },  /* default -> RESTART */
    { "sig_usr1",     MONCP_SIGNAL,  SIGUSR1,         0,       64 },
    { "sig_hup",      MONCP_SIGNAL,  SIGHUP,          0,       64 },
    { "sig_realtime", MONCP_SIGNAL,  -1,              0,       64 },  /* unknown signal -> sig_default[16] */
    { "still_alive",  MONCP_ALIVE,   0,               1,      -1  },

    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_mon_check_process_input(const mon_cp_test_case_t *tc)
{
    moncp_case_name = tc->test_name;

    int sig = tc->param;
    if (tc->kind == MONCP_SIGNAL && tc->param < 0)
        sig = SIGRTMIN + 3;   /* realtime signal: not in mon_sig_str's switch */

    pid_t pid = fork();
    if (pid == 0) {
        /* ---- child ---- */
        if (tc->kind == MONCP_EXIT) {
            _exit(tc->param);
        } else {
            /* SIGNAL or ALIVE: wait quietly to be killed / left running */
            for (;;) pause();
            _exit(0);
        }
    }

    /* ---- parent ---- */
    moncp_child = pid;

    if (tc->kind == MONCP_ALIVE) {
        /* leave it running; give it a moment to reach pause() */
        usleep(10 * 1000);
        return;
    }

    if (tc->kind == MONCP_SIGNAL) {
        usleep(10 * 1000);         /* let child reach pause() */
        kill(pid, sig);
    }

    /* wait until the child has terminated, but DO NOT reap it:
     * mon_check_process() must be the one to waitpid() it. */
    siginfo_t info;
    waitid(P_PID, pid, &info, WEXITED | WNOWAIT);
}
