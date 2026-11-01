/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_trigger_disconnection_analytics
 *
 * arg is a packed vap_svc_ext_t at the start of tda_arg_buf (bytes past
 * its size poisoned by the runner). new_bss gets a different BSSID so a
 * wrong-field read would show in the output.
 *
 * Cases: arg NULL (RETURN_ERR, nothing written), normal, vap_index 0,
 * and the longest line (connected_vap_index 0x80000000 printed as INT_MIN).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   tda_slot_mac[TDA_MAC_SZ + TDA_PAD];
char   tda_slot_tmp[TDA_TMP_SZ + TDA_PAD];
size_t tda_tmp_len;
int    tda_mac_calls;
alignas(16) char tda_arg_buf[sizeof(vap_svc_ext_t) + TDA_PAD];

analytics_event_trigger_disconnection_analytics_test_case_t analytics_event_trigger_disconnection_analytics_suite[] = {
    /* name            arg_null vap_index    bssid0 ret  expect                                                                     */
    { "arg_null",         1,     0,           0x00,  -1,  ""                                                                        },
    { "normal",           0,     14,          0x10,   0,  "Triggered Disconnection from vap_index 14 bssid:10:11:12:13:14:15"       },
    { "vap_index_zero",   0,     0,           0xa0,   0,  "Triggered Disconnection from vap_index 0 bssid:a0:a1:a2:a3:a4:a5"        },
    { "longest_line",     0,     0x80000000u, 0xfa,   0,  "Triggered Disconnection from vap_index -2147483648 bssid:fa:fb:fc:fd:fe:ff" },

    { NULL, 0, 0, 0, 0, NULL }  /* sentinel */
};

void construct_analytics_event_trigger_disconnection_analytics_input(const analytics_event_trigger_disconnection_analytics_test_case_t *tc)
{
    memset(tda_arg_buf, 0, sizeof(tda_arg_buf));
    vap_svc_ext_t *e = (vap_svc_ext_t *)tda_arg_buf;
    for (int b = 0; b < 6; b++) {
        e->last_connected_bss.external_ap.bssid[b] = (unsigned char)(tc->bssid0 + b);
        e->new_bss.external_ap.bssid[b] = 0xEE;          /* must NOT be printed */
    }
    e->connected_vap_index = tc->vap_index;
    memset(tda_slot_tmp, 0, sizeof(tda_slot_tmp));
    tda_tmp_len = 0;
    tda_mac_calls = 0;
}
