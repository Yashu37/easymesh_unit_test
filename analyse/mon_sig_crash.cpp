/*
 * HANDLER: mon_sig_crash
 *
 * Function copied VERBATIM from OneWifi lib/common/monitor.c:501. No fixes.
 * Its local array sigstr[MON_SIGSTR_SZ] is filled by mon_sig_str(); the
 * harness observes whether that write goes out of bounds under ASan.
 *
 * Scaffolding (NOT part of the function under test):
 *   - LOG() no-op stub + severity names and MON_SIGSTR_SZ from log.h/monitor.c
 *   - backtrace_dump() stub (real one lives in OneWifi's backtrace code)
 *   - mon_sig_str() is declared extern here; its single verbatim definition
 *     is in mon_check_process.cpp (both are always in the build).
 *
 * NOTE: mon_sig_crash() calls raise(signum) for every signal except
 * SIGUSR2, so a direct call is only safe with SIGUSR2; other signals are
 * driven from a forked child (see construct_mon_sig_crash.cpp).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define MON_SIGSTR_SZ 64                 /* verbatim from monitor.c:58 */
extern void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);
static void backtrace_dump(void) { /* stub: real one dumps a stack trace */ }

/* --- copied verbatim from lib/common/monitor.c:501 --- */
void mon_sig_crash(int signum)
{
    char sigstr[MON_SIGSTR_SZ];

    mon_sig_str(signum, sigstr, sizeof(sigstr));
    LOG(ALERT, "Signal %s received, generating stack dump...\n", sigstr);

    backtrace_dump();

    if (signum != SIGUSR2)
    {
        /* At this point the handler for this signal was reset (except for SIGUSR2) due to the SA_RESETHAND flag;
           so re-send the signal to ourselves in order to properly crash */
        raise(signum);
    }
}
