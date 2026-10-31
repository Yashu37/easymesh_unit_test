/*
 * TEST CASES / CONSTRUCTOR: construct_devinfo_get_inet_iface_config
 *
 * devinfo_get_inet_iface_config(if_name, config) fills config from cached
 * device-info values. Cases: the LAN bridge, the WAN bridge, and an
 * unknown interface (returns false). The constructor selects the interface
 * name into a runner-owned buffer (poisoned by the runner).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        dgi_ifname[64];
size_t      dgi_ifname_len;
const char *dgi_case_name;

devinfo_cfg_test_case_t devinfo_cfg_suite[] = {
    /* name              if_name        expect_ret */
    { "lan_bridge",      "brlan0",       1 },
    { "wan_bridge",      "erouter0",     1 },
    { "unknown_iface",   "wlan0",        0 },
    { "empty_iface",     "",             0 },

    { NULL, NULL, 0 }  /* sentinel */
};

void construct_devinfo_cfg_input(const devinfo_cfg_test_case_t *tc)
{
    dgi_case_name = tc->test_name;
    memset(dgi_ifname, 0, sizeof(dgi_ifname));
    snprintf(dgi_ifname, sizeof(dgi_ifname), "%s", tc->if_name);
    dgi_ifname_len = strlen(dgi_ifname);
}
