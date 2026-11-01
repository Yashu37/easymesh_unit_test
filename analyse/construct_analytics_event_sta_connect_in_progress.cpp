/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_sta_connect_in_progress
 *
 * arg is a packed bss_candidate_t at the start of scp_arg_buf (bytes past
 * its size poisoned by the runner).
 *
 * Cases: arg NULL (RETURN_ERR, nothing written), a normal BSSID, all-zero
 * BSSID, all-0xff BSSID (every MAC is 17 chars -> temp_str 42 chars).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   scp_slot_mac[SCP_MAC_SZ + SCP_PAD];
char   scp_slot_tmp[SCP_TMP_SZ + SCP_PAD];
size_t scp_tmp_len;
int    scp_mac_calls;
alignas(16) char scp_arg_buf[sizeof(bss_candidate_t) + SCP_PAD];

analytics_event_sta_connect_in_progress_test_case_t analytics_event_sta_connect_in_progress_suite[] = {
    /* name           arg_null  bssid byte  ret  expect                                         */
    { "arg_null",        1,       0x00,     -1,  ""                                            },
    { "normal_bssid",    0,       0x10,      0,  "start connection : bssid:10:11:12:13:14:15"  },
    { "zero_bssid",      0,       0x00,      0,  "start connection : bssid:00:01:02:03:04:05"  },
    { "ff_bssid",        0,       0xfa,      0,  "start connection : bssid:fa:fb:fc:fd:fe:ff"  },

    { NULL, 0, 0, 0, NULL }  /* sentinel */
};

void construct_analytics_event_sta_connect_in_progress_input(const analytics_event_sta_connect_in_progress_test_case_t *tc)
{
    memset(scp_arg_buf, 0, sizeof(scp_arg_buf));
    bss_candidate_t *c = (bss_candidate_t *)scp_arg_buf;
    for (int b = 0; b < 6; b++) c->external_ap.bssid[b] = (unsigned char)(tc->bssid0 + b);
    snprintf(c->external_ap.ssid, sizeof(c->external_ap.ssid), "uplink");
    memset(scp_slot_tmp, 0, sizeof(scp_slot_tmp));
    scp_tmp_len = 0;
    scp_mac_calls = 0;
}
