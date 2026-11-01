/*
 * HANDLER: os_nif_softwds_destroy
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_nif_linux.c. No fixes.
 * Local cmd[1024] is filled by snprintf(cmd, sizeof(cmd), "ip link del %s"),
 * so a long ifname is truncated, not overflowed. Caller input ifname is
 * poisoned by the runner; cmd is internal (auto-guarded by ASan).
 *
 * Scaffolding: cmd_log() is replaced by a stub that only records the
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

static int osd_cmd_log_stub(const char *cmd)
{
    osd_cmd_len = strlen(cmd);
    osd_calls++;
    return osd_exit << 8;
}
#define cmd_log(c) osd_cmd_log_stub(c)

/* --- copied verbatim from lib/osa/os_nif_linux.c --- */
bool os_nif_softwds_destroy(
        char* ifname)
{
    char cmd[1024];
    int rc;

    snprintf(cmd, sizeof(cmd), "ip link del %s", ifname);
    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        LOG(ERR, "%s: Failed to destroy softwds link ('%s')", __func__, cmd);
        return false;
    }

    return true;
}
