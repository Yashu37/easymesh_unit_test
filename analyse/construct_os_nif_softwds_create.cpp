/*
 * TEST CASES / CONSTRUCTOR: construct_os_nif_softwds_create
 *
 * os_nif_softwds_create(ifname, parent, &mac, wrap) builds one shell command
 * into a local cmd[1024] (ifname appears 3 times, parent once); on failure it
 * reuses cmd for "ip link del <ifname>". cmd_log is stubbed.
 * Cases: normal success, wrap = Y, create fails (cleanup path), 255-char
 * ifname (3 x 255 -> ~904 chars), 255-char parent, both 255 (~1155 chars,
 * truncated to 1023 by snprintf) with the failure path, and empty names.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   osc_ifname[256], osc_parent[256];
size_t osc_ifname_len, osc_parent_len;
size_t osc_max_cmd_len;
int    osc_calls, osc_create_exit;

os_nif_softwds_test_case_t os_nif_softwds_create_suite[] = {
    /* name                   ifname       if_fill parent   par_fill wrap exit ret */
    { "normal",               "wds0",        0,    "wifi0",   0,      0,   0,   1 },
    { "wrap_yes",             "wds1",        0,    "wifi1",   0,      1,   0,   1 },
    { "create_fails",         "wds2",        0,    "wifi2",   0,      0,   1,   0 },
    { "ifname_255",           NULL,        255,    "wifi0",   0,      0,   0,   1 },
    { "parent_255",           "wds0",        0,    NULL,    255,      1,   0,   1 },
    { "both_255_fail",        NULL,        255,    NULL,    255,      1,   1,   0 },
    { "empty_names",          "",            0,    "",        0,      0,   0,   1 },

    { NULL, NULL, 0, NULL, 0, 0, 0, 0 }  /* sentinel */
};

static void fill(char *dst, size_t dsz, const char *lit, int n, char ch)
{
    memset(dst, 0, dsz);
    if (n > 0) memset(dst, ch, (size_t)n < dsz ? (size_t)n : dsz - 1);
    else       snprintf(dst, dsz, "%s", lit);
}

void construct_os_nif_softwds_create_input(const os_nif_softwds_test_case_t *tc)
{
    fill(osc_ifname, sizeof(osc_ifname), tc->ifname, tc->if_fill, 'i');
    fill(osc_parent, sizeof(osc_parent), tc->parent, tc->par_fill, 'p');
    osc_ifname_len  = strlen(osc_ifname);
    osc_parent_len  = strlen(osc_parent);
    osc_max_cmd_len = 0;
    osc_calls       = 0;
    osc_create_exit = tc->create_exit;
}
