/*
 * HANDLER: os_nif_gateway_del
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_nif_linux.c. No fixes.
 * Local iproute[128] is filled by snprintf(iproute, sizeof(iproute), ...),
 * so a long ifname is truncated, not overflowed. Caller input ifname is
 * poisoned by the runner; iproute is internal (auto-guarded by ASan).
 *
 * Scaffolding: system() is replaced by a stub that only records the command
 * (so the test never changes the host routing table); os_ipaddr_t and
 * PRI/FMT macros copied verbatim from lib/osa/os_types.h + lib/const/const.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
char   ogd_last_cmd[512];
size_t ogd_last_cmd_len;
static int ogd_system_stub(const char *cmd)
{
    ogd_last_cmd_len = strlen(cmd);
    snprintf(ogd_last_cmd, sizeof(ogd_last_cmd), "%s", cmd);
    return 0;
}
#define system(c) ogd_system_stub(c)

/* --- copied verbatim from lib/osa/os_nif_linux.c --- */
bool os_nif_gateway_del(char* ifname, os_ipaddr_t gwaddr)
{
    char iproute[128];

    snprintf(iproute, sizeof(iproute),
            "ip route del default via "PRI(os_ipaddr_t)" dev %s", FMT(os_ipaddr_t, gwaddr), ifname);

    return system(iproute) == 0;
}
