/*
 * HANDLER: mon_sig_str
 *
 * Function copied VERBATIM from OneWifi lib/common/monitor.c:541. No fixes.
 * This is the canonical definition for the whole harness: the other
 * monitor handlers (mon_check_process / mon_sig_crash / mon_sig_forward)
 * declare it extern and call it.
 *
 * It takes a CALLER-OWNED buffer (sigstr, sigstr_sz) and writes into it
 * with snprintf, and uses a local sig_default[16] for signals not in the
 * switch. Both writes are what the harness watches under ASan.
 *
 * The only non-verbatim change is the (char *) casts on the string
 * literals, required because the file is compiled as C++ (in C the
 * assignments need no cast); the logic is unchanged.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

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
