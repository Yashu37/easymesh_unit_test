/*
 * TEST CASES / CONSTRUCTOR: construct_em_config_channel_scan
 *
 * data (a channel_scan_request_t) lives at eccs_req_buf; the wifi_mgr stand-in
 * at eccs_mgr_buf. The wifi_prop maps iface "wlan0"->radio 0 (mac 10..),
 * "wlan1"->radio 1 (mac 20..). scan_req->ruid is set per case.
 *
 * Cases: match_r1 (ruid = wlan1 mac -> scan init for radio 1), no_match
 * (ruid matches nothing), null_data, small_len (len < struct), mgr_null.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char eccs_mgr_buf[sizeof(wifi_mgr_t) + ECCS_PAD];
alignas(16) char eccs_req_buf[sizeof(channel_scan_request_t) + ECCS_PAD];
int  eccs_mgr_null, eccs_iface_count, eccs_scan_init_calls, eccs_scan_init_radio;
char eccs_iface_name[8][32];
unsigned char eccs_iface_mac[8][6];

em_eccs_test_case_t em_config_channel_scan_suite[] = {
    /* name        data_null small_len mgr_null  want_calls want_radio */
    { "match_r1",     0,      0,        0,         1,         1 },
    { "no_match",     0,      0,        0,         0,        -1 },
    { "null_data",    1,      0,        0,         0,        -1 },
    { "small_len",    0,      1,        0,         0,        -1 },
    { "mgr_null",     0,      0,        1,         0,        -1 },
    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_config_channel_scan_input(const em_eccs_test_case_t *tc)
{
    memset(eccs_mgr_buf, 0, sizeof(eccs_mgr_buf));
    memset(eccs_req_buf, 0, sizeof(eccs_req_buf));

    wifi_mgr_t *m = (wifi_mgr_t *)eccs_mgr_buf;
    wifi_platform_property_t *wp = &m->hal_cap.wifi_prop;
    for (int k = 0; k < 8; k++) wp->radio_interface_map[k].radio_index = -1;
    snprintf(wp->radio_interface_map[0].interface_name, 32, "wlan0"); wp->radio_interface_map[0].radio_index = 0;
    snprintf(wp->radio_interface_map[1].interface_name, 32, "wlan1"); wp->radio_interface_map[1].radio_index = 1;
    eccs_iface_count = 2;
    unsigned char m0[6] = {0x10,0x11,0x12,0x13,0x14,0x15}; snprintf(eccs_iface_name[0], 32, "wlan0"); memcpy(eccs_iface_mac[0], m0, 6);
    unsigned char m1[6] = {0x20,0x21,0x22,0x23,0x24,0x25}; snprintf(eccs_iface_name[1], 32, "wlan1"); memcpy(eccs_iface_mac[1], m1, 6);

    channel_scan_request_t *req = (channel_scan_request_t *)eccs_req_buf;
    if (strcmp(tc->test_name, "match_r1") == 0)       memcpy(req->ruid, m1, 6);  /* -> radio 1 */
    else { unsigned char q[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; memcpy(req->ruid, q, 6); }

    eccs_mgr_null = tc->mgr_null;
    eccs_scan_init_calls = 0;
    eccs_scan_init_radio = -1;
}
