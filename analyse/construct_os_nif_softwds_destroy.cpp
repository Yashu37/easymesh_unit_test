/*
 * TEST CASES / CONSTRUCTOR: construct_os_nif_softwds_destroy
 *
 * os_nif_softwds_destroy(ifname) builds "ip link del <ifname>" into a local
 * cmd[1024] and runs it through cmd_log (stubbed). The fixed part is 12
 * chars, so cmd overflows only past a 1011-char ifname -- the runner-owned
 * ifname buffer is 2048 so that limit can be reached and passed.
 * Cases: normal, command fails, empty, 255, 1011 (exactly 1023 chars),
 * 1012 (one past -> truncated) and 2047 (max that fits the buffer).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   osd_ifname[2048];
size_t osd_ifname_len;
size_t osd_cmd_len;
int    osd_calls, osd_exit;

os_nif_softwds_destroy_test_case_t os_nif_softwds_destroy_suite[] = {
    /* name              ifname    fill  exit ret */
    { "normal",          "wds0",      0,   0,  1 },
    { "cmd_fails",       "wds0",      0,   1,  0 },
    { "empty_ifname",    "",          0,   0,  1 },
    { "ifname_255",      NULL,      255,   0,  1 },
    { "ifname_1011",     NULL,     1011,   0,  1 },   /* 12 + 1011 = 1023 */
    { "ifname_1012",     NULL,     1012,   0,  1 },   /* truncated to 1023 */
    { "ifname_2047",     NULL,     2047,   1,  0 },

    { NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_os_nif_softwds_destroy_input(const os_nif_softwds_destroy_test_case_t *tc)
{
    memset(osd_ifname, 0, sizeof(osd_ifname));
    if (tc->fill > 0)
        memset(osd_ifname, 'd', (size_t)tc->fill < sizeof(osd_ifname) ? (size_t)tc->fill : sizeof(osd_ifname) - 1);
    else
        snprintf(osd_ifname, sizeof(osd_ifname), "%s", tc->ifname);
    osd_ifname_len = strlen(osd_ifname);
    osd_cmd_len    = 0;
    osd_calls      = 0;
    osd_exit       = tc->exit_status;
}
