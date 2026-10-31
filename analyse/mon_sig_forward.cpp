/*
 * HANDLER: mon_sig_forward
 *
 * Function copied VERBATIM from OneWifi lib/common/monitor.c:521. No fixes.
 * Its local array sigstr[MON_SIGSTR_SZ] is filled by mon_sig_str(); the
 * harness observes whether that write goes out of bounds under ASan.
 *
 * Scaffolding (NOT part of the function under test):
 *   - LOG() no-op stub + severity names and MON_SIGSTR_SZ
 *   - mon_sig_forward_pid: in OneWifi this is a static file-scope global
 *     (monitor.c:100); here it is a plain global so the test can set the
 *     target pid. Behaviour of mon_sig_forward() is unchanged.
 *   - mon_sig_str() declared extern; its single verbatim definition is in
 *     mon_check_process.cpp (always in the build).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define MON_SIGSTR_SZ 64                 /* verbatim from monitor.c:58 */
extern void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);

/* verbatim from monitor.c:100 (static there; global here so tests can set it) */
pid_t mon_sig_forward_pid = 0;

/* --- copied verbatim from lib/common/monitor.c:521 --- */
void mon_sig_forward(int signum)
{
    if (mon_sig_forward_pid > 0)
    {
        char sigstr[MON_SIGSTR_SZ];

        mon_sig_str(signum, sigstr, sizeof(sigstr));

        LOG(DEBUG, "Forwarding signal %s to pid %d\n", sigstr, mon_sig_forward_pid);
        if (kill(mon_sig_forward_pid, signum) != 0)
        {
            LOG(DEBUG, "SIGNAL %s was not delivered as process %d is dead.\n", sigstr, mon_sig_forward_pid);
            mon_sig_forward_pid = 0;
        }
    }
}
