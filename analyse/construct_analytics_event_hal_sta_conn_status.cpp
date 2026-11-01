/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_hal_sta_conn_status
 *
 * arg is an rdk_sta_data_t at the start of scs_arg_buf (bytes past its size
 * poisoned by the runner). connect_status selects the snprintf.
 *
 * Cases: arg NULL, connected, disconnected, AP not found, an unknown
 * status (no output), and vap_index INT_MIN / INT_MAX with bssid ff:..:ff
 * (longest possible line).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

char   scs_slot[SCS_SLOT_SZ + SCS_PAD];
size_t scs_len;
int    scs_calls;
alignas(16) char scs_arg_buf[sizeof(rdk_sta_data_t) + SCS_PAD];

analytics_event_hal_sta_conn_status_test_case_t analytics_event_hal_sta_conn_status_suite[] = {
    /* name                 arg_null status                                vap_index  ret calls len */
    { "arg_null",              1,   wifi_connection_status_connected,         1,      -1,   0,   0 },
    { "connected",             0,   wifi_connection_status_connected,         1,       0,   1,  47 },
    { "disconnected",          0,   wifi_connection_status_disconnected,      2,       0,   1,  50 },
    { "ap_not_found",          0,   wifi_connection_status_ap_not_found,     14,       0,   1,  40 },
    { "unknown_status",        0,   99,                                       1,       0,   0,   0 },
    { "connected_int_min",     0,   wifi_connection_status_connected,   INT_MIN,       0,   1,  57 },
    { "disconnected_int_min",  0,   wifi_connection_status_disconnected, INT_MIN,      0,   1,  60 },
    { "ap_not_found_int_max",  0,   wifi_connection_status_ap_not_found, INT_MAX,      0,   1,  48 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_analytics_event_hal_sta_conn_status_input(const analytics_event_hal_sta_conn_status_test_case_t *tc)
{
    memset(scs_arg_buf, 0, sizeof(scs_arg_buf));
    rdk_sta_data_t *d = (rdk_sta_data_t *)scs_arg_buf;
    d->stats.connect_status = tc->status;
    d->stats.vap_index = tc->vap_index;
    unsigned char ff = (tc->vap_index == INT_MIN || tc->vap_index == INT_MAX) ? 0xff : 0x00;
    for (int b = 0; b < 6; b++) d->bss_info.bssid[b] = ff ? ff : (unsigned char)(0x10 + b);
    scs_len = 0;
    scs_calls = 0;
}
