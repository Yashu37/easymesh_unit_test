/*
 * HANDLER: mon_check_process
 *
 * Function copied VERBATIM from OneWifi lib/common/monitor.c:275. No fixes.
 * Its local array sigstr[MON_SIGSTR_SZ] is filled by the helper
 * mon_sig_str() (whose own verbatim copy lives in mon_sig_str.cpp and is
 * declared extern below), so the harness observes whether either writes
 * out of bounds under ASan.
 *
 * LOG()/severity names come from OneWifi's lib/log/log.h (not in this
 * harness); a no-op LOG stub and the two #defines are provided ONLY so the
 * verbatim bodies compile. They do not change what the functions do.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding (stubs / defines, not part of the functions) --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define MON_SIGSTR_SZ     64   /* verbatim from monitor.c:58 */
#define MON_EXIT_RESTART  64   /* verbatim from monitor.h:30 */

void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);

/* --- copied verbatim from lib/common/monitor.c:275 --- */
bool mon_check_process(pid_t child, int *exit_status)
{
    int ret;
    int status = 0;

    *exit_status = -1;

    /*
     *  Check if the child exited; if it did check why:
     *      - If it died due to a signal, it probably crashed or got killed by the counter watcher, in which case we should restart it
     *      - If it exited regularly, use the child return status to exit
     */
    ret = waitpid(child, &status, WNOHANG);
    if (ret == 0)
    {
        /* Child is still alive, return true */
        return true;
    }
    else if (ret == -1)
    {
        /* This is an abnormal condition; restart the child */
        LOG(ERR, "Child %d suddenly disappeared: %s\n", child, strerror(errno));
        *exit_status = MON_EXIT_RESTART;
        return false;
    }

    /*
     * ret is above 0, this means that the child died. Determine the cause of death and extract the exit status
     */
    if (WIFEXITED(status))
    {
        /* Child exited normally, just return it's status */
        *exit_status  = WEXITSTATUS(status);

        LOG(NOTICE, "Child %d exited with status %d ...\n", child, *exit_status);
    }
    else if (WIFSIGNALED(status))
    {
        char sigstr[MON_SIGSTR_SZ];

        mon_sig_str(WTERMSIG(status), sigstr, sizeof(sigstr));
        /* The child was terminated by a signal, check what to do */
        switch (WTERMSIG(status))
        {
            case SIGTERM:
            case SIGINT:
                LOG(NOTICE, "Child terminated by non-fatal signal %s, exiting ...\n", sigstr);
                *exit_status = WEXITSTATUS(status);
                break;

            default:
                LOG(NOTICE, "Child terminated abruptly by signal %s, restarting ...\n", sigstr);
                *exit_status = MON_EXIT_RESTART;
                break;
        }
    }

    return false;
}

