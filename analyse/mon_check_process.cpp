/*
 * HANDLER: mon_check_process
 *
 * Function copied VERBATIM from OneWifi lib/common/monitor.c:275. No fixes.
 * Its local array sigstr[MON_SIGSTR_SZ] is filled by the helper
 * mon_sig_str() (also copied verbatim here, from monitor.c:541), so both
 * are included and the harness observes whether either writes out of
 * bounds under ASan.
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

/* --- copied verbatim from lib/common/monitor.c:541 --- */
void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz)
{
    char sig_default[16];
    char *sig;

    switch (signum)
    {
        case SIGHUP:       sig = (char *)"SIGHUP";      break;
        case SIGINT:       sig = (char *)"SIGINT";      break;
        case SIGQUIT:      sig = (char *)"SIGQUIT";     break;
        case SIGILL:       sig = (char *)"SIGILL";      break;
        case SIGTRAP:      sig = (char *)"SIGTRAP";     break;
        case SIGABRT:      sig = (char *)"SIGABRT";     break;
        case SIGBUS:       sig = (char *)"SIGBUS";      break;
        case SIGFPE:       sig = (char *)"SIGFPE";      break;
        case SIGKILL:      sig = (char *)"SIGKILL";     break;
        case SIGUSR1:      sig = (char *)"SIGUSR1";     break;
        case SIGSEGV:      sig = (char *)"SIGSEGV";     break;
        case SIGUSR2:      sig = (char *)"SIGUSR2";     break;
        case SIGPIPE:      sig = (char *)"SIGPIPE";     break;
        case SIGALRM:      sig = (char *)"SIGALRM";     break;
        case SIGTERM:      sig = (char *)"SIGTERM";     break;
        case SIGCHLD:      sig = (char *)"SIGCHLD";     break;
        case SIGCONT:      sig = (char *)"SIGCONT";     break;
        case SIGSTOP:      sig = (char *)"SIGSTOP";     break;
        case SIGTSTP:      sig = (char *)"SIGTSTP";     break;
        case SIGTTIN:      sig = (char *)"SIGTTIN";     break;
        case SIGTTOU:      sig = (char *)"SIGTTOU";     break;
        case SIGURG:       sig = (char *)"SIGURG";      break;
        case SIGXCPU:      sig = (char *)"SIGXCPU";     break;
        case SIGXFSZ:      sig = (char *)"SIGXFSZ";     break;
        case SIGVTALRM:    sig = (char *)"SIGVTALRM";   break;
        case SIGPROF:      sig = (char *)"SIGPROF";     break;
        case SIGWINCH:     sig = (char *)"SIGWINCH";    break;
        case SIGIO:        sig = (char *)"SIGIO";       break;
        case SIGPWR:       sig = (char *)"SIGPWR";      break;
        case SIGSYS:       sig = (char *)"SIGSYS";      break;

        default:
            snprintf(sig_default, sizeof(sig_default), "%d", signum);
            sig = sig_default;
            break;
    }

    snprintf(sigstr, sigstr_sz, "%s (%s)", sig, strsignal(signum));
}
