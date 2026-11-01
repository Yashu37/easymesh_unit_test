/*
 * TEST CASES / CONSTRUCTOR: construct_pktgen_configure
 *
 * pktgen_configure(if_name, dest_mac, packet_size) issues 7 pgctrl
 * commands (reset, add_device, then 5 on dev_path). if_name / dest_mac are
 * runner buffers (tails poisoned by the runner).
 *
 * Cases: success, reset fails (continues), add_device fails, each later
 * step failing (3..7), if_name of 4078 chars (dev_path exactly 4095),
 * 4079 / 10000 chars (dev_path truncated to 4095), and a 3000-char MAC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   pgf_slot[PGF_SLOT_SZ + PGF_SLOT_PAD];
size_t pgf_dev_len, pgf_max_path;
int    pgf_calls, pgf_fail_at;
char   pgf_ifname[PGF_STR_SZ];
char   pgf_mac[PGF_STR_SZ];

pktgen_configure_test_case_t pktgen_configure_suite[] = {
    /* name               if_len mac_len fail_at ret calls dev_len */
    { "success",              5,   17,     0,      0,   7,   22 },
    { "reset_fails",          5,   17,     1,      0,   7,   22 },
    { "add_device_fails",     5,   17,     2,     -1,   2,    0 },
    { "queue_min_fails",      5,   17,     3,     -1,   3,   22 },
    { "queue_max_fails",      5,   17,     4,     -1,   4,   22 },
    { "count_fails",          5,   17,     5,     -1,   5,   22 },
    { "pkt_size_fails",       5,   17,     6,     -1,   6,   22 },
    { "dst_mac_fails",        5,   17,     7,     -1,   7,   22 },
    { "if_name_4078",      4078,   17,     0,      0,   7, 4095 },
    { "if_name_4079",      4079,   17,     0,      0,   7, 4095 },
    { "if_name_10000",    10000,   17,     0,      0,   7, 4095 },
    { "mac_3000",             5, 3000,     0,      0,   7,   22 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_pktgen_configure_input(const pktgen_configure_test_case_t *tc)
{
    memset(pgf_ifname, 0, sizeof(pgf_ifname));
    memset(pgf_mac, 0, sizeof(pgf_mac));
    if (tc->if_len == 5) snprintf(pgf_ifname, sizeof(pgf_ifname), "wlan0");
    else memset(pgf_ifname, 'i', (size_t)tc->if_len);
    if (tc->mac_len == 17) snprintf(pgf_mac, sizeof(pgf_mac), "aa:bb:cc:dd:ee:ff");
    else memset(pgf_mac, 'm', (size_t)tc->mac_len);
    pgf_fail_at = tc->fail_at;
    pgf_calls = 0;
    pgf_dev_len = 0;
    pgf_max_path = 0;
}
