/*
 * HANDLER: os_nif_softwds_create
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_nif_linux.c. No fixes.
 * Local cmd[1024] is filled by snprintf(cmd, sizeof(cmd), ...) both for the
 * create command and for the "ip link del" cleanup, so long ifname/parent
 * are truncated, not overflowed. Caller inputs ifname, parent and mac are
 * poisoned by the runner; cmd is internal (auto-guarded by ASan).
 *
 * Scaffolding: cmd_log() is replaced by a stub that only records each
 * command (never runs "ip link" on the host) and returns the exit status
 * chosen by the test case; LOG no-op.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)

static int osc_cmd_log_stub(const char *cmd)
{
    size_t l = strlen(cmd);
    if (l > osc_max_cmd_len) osc_max_cmd_len = l;
    osc_calls++;
    /* first call = create; any later call = cleanup ("ip link del") */
    return (osc_calls == 1) ? (osc_create_exit << 8) : 0;
}
#define cmd_log(c) osc_cmd_log_stub(c)

/* --- copied verbatim from lib/osa/os_nif_linux.c --- */
bool os_nif_softwds_create(
        char* ifname,
        char* parent,
        os_macaddr_t* mac,
        bool wrap)
{
    char cmd[1024];
    int rc;

    snprintf(cmd, sizeof(cmd),
             "ip link add link %s name %s type softwds && "
             "echo " PRI(os_macaddr_t) " > /sys/class/net/%s/softwds/addr && "
             "echo %c > /sys/class/net/%s/softwds/wrap",
             parent, ifname,
             FMT(os_macaddr_t, *mac), ifname,
             wrap ? 'Y' : 'N', ifname);
    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        LOG(ERR, "%s: Failed to create softwds link ('%s')", __func__, cmd);
        snprintf(cmd, sizeof(cmd), "ip link del %s", ifname);
        rc = cmd_log(cmd);
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
            LOG(ERR, "%s: Failed to clean up ('%s'), expect trouble", __func__, cmd);
        return false;
    }

    return true;
}
