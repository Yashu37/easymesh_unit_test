/*
 * TEST CASES / CONSTRUCTOR: construct_os_nif_gateway_set
 *
 * os_nif_gateway_set(ifname, gw) builds "ip route add default via <gw> dev
 * <ifname>" into a local iproute[128] and runs it (system() is stubbed).
 * Cases: a normal ifname, an empty one, one long enough to hit exactly the
 * 127-char limit, one longer than iproute, and the longest that fits the
 * caller buffer (255). A max gateway (255.255.255.255) is used for the long
 * ones so the fixed part of the command is as long as possible.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        ogs_ifname[256];
size_t      ogs_ifname_len;
os_ipaddr_t ogs_gw;

os_nif_gw_test_case_t os_nif_gateway_set_suite[] = {
    /* name              ifname      fill  gw                     */
    { "normal_eth0",     "eth0",       0,  {{192, 168, 1, 1}}     },
    { "empty_ifname",    "",           0,  {{10, 0, 0, 1}}        },
    { "fill_to_limit",   NULL,        82,  {{255, 255, 255, 255}} },  /* 45 + 82 = 127 chars */
    { "longer_than_buf", NULL,       200,  {{255, 255, 255, 255}} },
    { "ifname_255",      NULL,       255,  {{255, 255, 255, 255}} },

    { NULL, NULL, 0, {{0, 0, 0, 0}} }  /* sentinel */
};

void construct_os_nif_gateway_set_input(const os_nif_gw_test_case_t *tc)
{
    memset(ogs_ifname, 0, sizeof(ogs_ifname));
    if (tc->fill > 0)
        memset(ogs_ifname, 'w', (size_t)tc->fill < sizeof(ogs_ifname) ? (size_t)tc->fill : sizeof(ogs_ifname) - 1);
    else
        snprintf(ogs_ifname, sizeof(ogs_ifname), "%s", tc->ifname);
    ogs_ifname_len = strlen(ogs_ifname);
    ogs_gw = tc->gw;
}
