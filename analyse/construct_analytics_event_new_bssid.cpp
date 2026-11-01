/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_new_bssid
 *
 * arg is a packed vap_svc_ext_t at the start of anb_arg_buf (bytes past
 * its size poisoned by the runner). last_connected_bss gets a different
 * BSSID / vap_index / freq so a wrong-field read would show in the output.
 *
 * Cases: arg NULL (RETURN_ERR, nothing written), 2.4 GHz, 5 GHz, 6 GHz,
 * and the longest line (vap_index and freq 0x80000000 printed as INT_MIN).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   anb_slot_mac[ANB_MAC_SZ + ANB_PAD];
char   anb_slot_tmp[ANB_TMP_SZ + ANB_PAD];
size_t anb_tmp_len;
int    anb_mac_calls;
alignas(16) char anb_arg_buf[sizeof(vap_svc_ext_t) + ANB_PAD];

analytics_event_new_bssid_test_case_t analytics_event_new_bssid_suite[] = {
    /* name            arg_null vap_index    freq         bssid0 ret  expect */
    { "arg_null",         1,     0,           0,           0x00,  -1,  "" },
    { "band_2g",          0,     14,          2437,        0x10,   0,  "new bssid : vap_index:14 bssid:10:11:12:13:14:15 freq:2437" },
    { "band_5g",          0,     15,          5180,        0xa0,   0,  "new bssid : vap_index:15 bssid:a0:a1:a2:a3:a4:a5 freq:5180" },
    { "band_6g",          0,     16,          5955,        0x00,   0,  "new bssid : vap_index:16 bssid:00:01:02:03:04:05 freq:5955" },
    { "longest_line",     0,     0x80000000u, 0x80000000u, 0xfa,   0,  "new bssid : vap_index:-2147483648 bssid:fa:fb:fc:fd:fe:ff freq:-2147483648" },

    { NULL, 0, 0, 0, 0, 0, NULL }  /* sentinel */
};

void construct_analytics_event_new_bssid_input(const analytics_event_new_bssid_test_case_t *tc)
{
    memset(anb_arg_buf, 0, sizeof(anb_arg_buf));
    vap_svc_ext_t *e = (vap_svc_ext_t *)anb_arg_buf;
    for (int b = 0; b < 6; b++) {
        e->new_bss.external_ap.bssid[b] = (unsigned char)(tc->bssid0 + b);
        e->last_connected_bss.external_ap.bssid[b] = 0xEE;   /* must NOT be printed */
    }
    e->new_bss.vap_index = tc->vap_index;
    e->new_bss.external_ap.freq = tc->freq;
    e->last_connected_bss.vap_index = 99;
    e->last_connected_bss.external_ap.freq = 9999;
    e->connected_vap_index = 98;
    memset(anb_slot_tmp, 0, sizeof(anb_slot_tmp));
    anb_tmp_len = 0;
    anb_mac_calls = 0;
}
