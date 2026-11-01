/*
 * TEST CASES / CONSTRUCTOR: construct_os_nif_list_get
 *
 * os_nif_list_get(&list) reads /proc/net/dev line by line into buf[256],
 * matches "^[\t ]*([-a-zA-Z0-9]+):" with rm[2], and copies group 1 into a
 * new entry's le_ifname[64]. fopen("/proc/net/dev") is redirected to the
 * runner buffer onlg_data (except the real_proc_net_dev case).
 *
 * Cases: the real file, a normal 2-interface file, names of 63/64/200
 * chars (63 fits, longer ones are truncated to 63), a 600-char line (longer
 * than buf, so fgets splits it), lines without a colon, an empty file,
 * fopen failure, and more interfaces than the entry pool (malloc returns
 * NULL -> error path frees the list and returns false).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

unsigned char onlg_pool[ONLG_POOL_SLOTS][sizeof(struct os_nif_list_entry) + ONLG_SLOT_PAD];
int           onlg_pool_used;
char          onlg_data[16384];
size_t        onlg_data_len;
int           onlg_use_real, onlg_fopen_fail;

#define NETDEV_HDR \
    "Inter-|   Receive                            |  Transmit\n" \
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

os_nif_list_get_test_case_t os_nif_list_get_suite[] = {
    /* name                  kind             data                                              arg  ret count */
    { "real_proc_net_dev",   ONLG_REAL,       NULL,                                               0,  1,  -1 },
    { "normal_two_ifaces",   ONLG_DATA,       NETDEV_HDR "    lo: 1 2 0 0 0 0 0 0 1 2 0 0 0 0 0 0\n"
                                              "  eth0: 9 9 0 0 0 0 0 0 9 9 0 0 0 0 0 0\n",       0,  1,   2 },
    { "name_63_fits",        ONLG_NAME_LEN,   NULL,                                              63,  1,   1 },
    { "name_64_truncated",   ONLG_NAME_LEN,   NULL,                                              64,  1,   1 },
    { "name_200_truncated",  ONLG_NAME_LEN,   NULL,                                             200,  1,   1 },
    { "line_600_split",      ONLG_LONG_LINE,  NULL,                                             600,  1,  -1 },
    { "no_colon_lines",      ONLG_DATA,       NETDEV_HDR "eth0 1 2 3\nwlan0 4 5 6\n",            0,  1,   0 },
    { "empty_file",          ONLG_DATA,       "",                                                 0,  1,   0 },
    { "fopen_fails",         ONLG_FOPEN_FAIL, NULL,                                               0,  0,   0 },
    { "more_than_pool",      ONLG_MANY,       NULL,                        ONLG_POOL_SLOTS + 5,  0,   0 },

    { NULL, 0, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_os_nif_list_get_input(const os_nif_list_get_test_case_t *tc)
{
    memset(onlg_data, 0, sizeof(onlg_data));
    memset(onlg_pool, 0xAB, sizeof(onlg_pool));
    onlg_pool_used  = 0;
    onlg_data_len   = 0;
    onlg_use_real   = (tc->kind == ONLG_REAL);
    onlg_fopen_fail = (tc->kind == ONLG_FOPEN_FAIL);

    size_t off = 0;
    switch (tc->kind) {
    case ONLG_DATA:
        off = (size_t)snprintf(onlg_data, sizeof(onlg_data), "%s", tc->data);
        break;
    case ONLG_NAME_LEN:
        off = (size_t)snprintf(onlg_data, sizeof(onlg_data), "%s  ", NETDEV_HDR);
        memset(onlg_data + off, 'a', (size_t)tc->arg);
        off += (size_t)tc->arg;
        off += (size_t)snprintf(onlg_data + off, sizeof(onlg_data) - off, ": 1 2 0 0 0 0 0 0 1 2 0 0 0 0 0 0\n");
        break;
    case ONLG_LONG_LINE:
        /* "x...x" (arg chars) then ":" -- no newline within buf's 255 */
        memset(onlg_data, 'x', (size_t)tc->arg);
        off = (size_t)tc->arg;
        off += (size_t)snprintf(onlg_data + off, sizeof(onlg_data) - off, ": 1 2 3\n");
        break;
    case ONLG_MANY:
        for (int i = 0; i < tc->arg; i++)
            off += (size_t)snprintf(onlg_data + off, sizeof(onlg_data) - off, " if%d: 0 0\n", i);
        break;
    default:
        break;
    }
    onlg_data_len = off;
}
